package crosspost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dghubble/oauth1"
)

// NewMastodonCrossPost creates a new MastodonCrossPost.
//
// Example:
//
//	mastodonCrossPost := NewMastodonCrossPost(
//	    "https://mastodon.social",
//	    "123456789", // Mastodon account ID
//	    "https://example.com/callback",
//	    "123456789", // Twitter OAuth 2 client ID
//	    "123456789", // Twitter OAuth 2 client secret
//	    "https://api.twitter.com/oauth2/authorize",
//	    "https://api.twitter.com/oauth2/token",
//	    "https://api.twitter.com/1.1/statuses/update.json",
//	)
//	mastodonCrossPost.CrossPostTweets()
func NewMastodonCrossPost(mastodonURL, accountID, redirectURI, clientID, clientSecret, consumerKey, consumerSecret, accessToken, accessTokenSecret, twitterAuthorizeUrl, twitterOAuth2TokenUrl, twitterPostTweetUrl, twitterMediaUploadUrl string) *MastodonCrossPost {
	oauthConfig := oauth1.NewConfig(consumerKey, consumerSecret)
	oauthToken := oauth1.NewToken(accessToken, accessTokenSecret)
	httpClient := oauthConfig.Client(oauth1.NoContext, oauthToken)
	return &MastodonCrossPost{
		accountID:             accountID,
		baseURL:               mastodonURL,
		clientID:              clientID,
		clientSecret:          clientSecret,
		createdAt:             time.Now(),
		lastSeenTootID:        "",
		lock:                  sync.RWMutex{},
		redirectURI:           redirectURI,
		tootToTweetMap:        make(map[string]tootMapEntry),
		twitterAuthorizeUrl:   twitterAuthorizeUrl,
		twitterOAuth2TokenUrl: twitterOAuth2TokenUrl,
		twitterPostTweetUrl:   twitterPostTweetUrl,
		twitterToken:          &TwitterOAuthTokenResponse{},
		twitterTokenExpiry:    time.Time{},
		twitterMediaUploadUrl: twitterMediaUploadUrl,
		oauthClient:           httpClient,
	}
}

type PostTweetReplyRequest struct {
	InReplyToTweetID string `json:"in_reply_to_tweet_id,omitempty"`
}

type TweetMediaRequest struct {
	MediaIDs []string `json:"media_ids,omitempty"`
}

type PostTweetRequest struct {
	Text  string                 `json:"text"`
	Reply *PostTweetReplyRequest `json:"reply,omitempty"`
	Media *TweetMediaRequest     `json:"media,omitempty"`
}

type PostTweetData struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type PostTweetResponse struct {
	Data PostTweetData
}

type MediaAttachment struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Toot struct {
	ID                 string            `json:"id"`
	InReplyToID        string            `json:"in_reply_to_id"`
	InReplyToAccountID string            `json:"in_reply_to_account_id"`
	Content            string            `json:"content"`
	CreatedAt          time.Time         `json:"created_at"`
	Reblog             interface{}       `json:"reblog"`
	MediaAttachments   []MediaAttachment `json:"media_attachments"`
}

type TwitterOAuthTokenRequest struct {
	Code         string `json:"code"`
	GrantType    string `json:"grant_type"`
	RedirectUri  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
	RefreshToken string `json:"refresh_token"`
}

type PostMediaRequest struct {
	MediaData string `json:"media_data"`
}

type PostMediaResponse struct {
	MediaIDString string `json:"media_id_string"`
}

type tootMapEntry struct {
	toot    Toot
	tweetID string
}
type MastodonCrossPost struct {
	accountID             string
	baseURL               string
	clientID              string
	clientSecret          string
	createdAt             time.Time
	lastSeenTootID        string
	lock                  sync.RWMutex
	redirectURI           string
	tootToTweetMap        map[string]tootMapEntry
	twitterAuthorizeUrl   string
	twitterOAuth2TokenUrl string
	twitterPostTweetUrl   string
	twitterToken          *TwitterOAuthTokenResponse
	twitterTokenExpiry    time.Time
	twitterMediaUploadUrl string
	oauthClient           *http.Client
}

type TwitterOAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

type OauthRequest struct {
	GrantType    string `json:"grant_type"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectUri  string `json:"redirect_uri"`
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type GetAccountResponse struct {
	ID string `json:"id"`
}

type authResponse struct {
	code  string
	state string
}

func (m *MastodonCrossPost) refreshTwitterToken() {
	log.Println("Starting loop to refresh Twitter token")
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		if time.Now().After(m.twitterTokenExpiry.Add(-60 * time.Minute)) {
			log.Println("Refreshing Twitter token")
			if err := m.getTwitterToken(true); err != nil {
				log.Println("Error refreshing Twitter token:", err)
			}
		}
	}
}

func (m *MastodonCrossPost) pruneTootCache() {
	m.lock.Lock()
	defer m.lock.Unlock()
	for k, v := range m.tootToTweetMap {
		if time.Now().After(v.toot.CreatedAt.Add(24 * time.Hour)) {
			delete(m.tootToTweetMap, k)
		}
	}
}

func (m *MastodonCrossPost) CrossPostTweets() {
	// Get initial Twitter token
	if err := m.getTwitterToken(false); err != nil {
		log.Fatal(err)
	}

	// Start loop to refresh token every minute
	go m.refreshTwitterToken()

	t := time.NewTicker(time.Minute)
	defer t.Stop()

	// loop for every tick
	for range t.C {
		m.pruneTootCache()

		// Get latest tweets
		toots, err := m.getLatestToots()
		if err != nil {
			log.Println("Error getting latest toots:", err, "Retrying in 1 minute")
			continue
		}

		// Sort toots by createdAt in reverse
		sort.Slice(toots, func(i, j int) bool {
			return toots[j].CreatedAt.After(toots[i].CreatedAt)
		})

		for _, toot := range toots {
			// Skip if Toot is a reply to another Toot
			if toot.InReplyToID != "" || toot.InReplyToAccountID != "" {
				if toot.InReplyToAccountID != m.accountID {
					continue
				}
			}
			// Skip if Toot was posted more than 1 hour before the bot was started
			if toot.CreatedAt.Before(time.Now().Add(-1 * time.Hour)) {
				continue
			}

			// Skip if the Toot is a reblog
			if toot.Reblog != nil {
				continue
			}

			// Check if we have already posted this toot
			if toot.ID <= m.lastSeenTootID {
				continue
			}

			for i := 1; i < 5; i++ {
				err := m.postToTwitter(toot)
				if err == nil {
					break
				}

				log.Println("Error posting to Twitter:", err, "Retrying in 20 seconds")
				time.Sleep(20 * time.Second)
				i++
			}
		}
	}
}

func (m *MastodonCrossPost) convertTootHTMLToText(content string) string {
	// Insert newlines between paragraphs
	content = strings.Replace(content, "</p>", "\n\n", -1)
	// Strip all HTML tags
	regexHTMLTag := regexp.MustCompile("<[^>]*>")
	content = regexHTMLTag.ReplaceAllString(content, "")
	// Unescape HTML codes
	regexHTMLCode := regexp.MustCompile("&#[a-zA-Z0-9]+;")
	content = regexHTMLCode.ReplaceAllStringFunc(content, func(s string) string {
		return html.UnescapeString(s)
	})
	content = strings.TrimSuffix(content, "</p>")
	return content
}

func (m *MastodonCrossPost) uploadMediaToTwitter(tempFile string) (mediaID string, err error) {
	signingClient := m.oauthClient

	// Post the tempFile to Twitter and retrieve the media id
	mediaUploadUrl := m.twitterMediaUploadUrl

	// Open the file
	file, err := os.Open(tempFile)
	if err != nil {
		return "", err
	}
	defer file.Close()
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	// Make INIT request to Twitter
	// work out media type from file contents
	mediaType := http.DetectContentType(fileBytes)
	// url encode the media type
	mediaType = url.QueryEscape(mediaType)
	log.Printf("Uploading %s to Twitter, media type: %s\n", tempFile, mediaType)
	req, err := http.NewRequest("POST", mediaUploadUrl+"?command=INIT&total_bytes="+strconv.Itoa(len(fileBytes))+"&media_type="+mediaType, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	log.Printf("Twitter INIT request: %+v\n", req)
	httpResp, err := signingClient.Do(req)
	if err != nil {
		return "", err
	}
	defer httpResp.Body.Close()
	// non-2xx response
	if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		// read the response body
		body, err := ioutil.ReadAll(httpResp.Body)
		if err != nil {
			return "", err
		}
		return "", errors.New("Twitter returned non-2xx response for INIT: " + strconv.Itoa(httpResp.StatusCode) + " " + string(body))
	}
	respBytes, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return "", err
	}
	var respData map[string]interface{}
	err = json.Unmarshal(respBytes, &respData)
	if err != nil {
		return "", err
	}
	mediaID = respData["media_id_string"].(string)

	// Make APPEND requests to Twitter
	segmentIndex := 0
	for {
		// Calculate the segment index
		segmentIndex = segmentIndex + 1
		segmentIndexStr := strconv.Itoa(segmentIndex - 1) // first segment is 0

		// Calculate the start and end of the segment
		segmentStart := (segmentIndex - 1) * 5 * 1024 * 1024
		segmentEnd := segmentIndex * 5 * 1024 * 1024
		if segmentEnd > len(fileBytes) {
			segmentEnd = len(fileBytes)
		}

		// Create a multipart form body with multiple parameters
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile("media", tempFile)
		if err != nil {
			return "", err
		}
		_, err = part.Write(fileBytes[segmentStart:segmentEnd])
		if err != nil {
			return "", err
		}
		writer.WriteField("command", "APPEND")
		writer.WriteField("media_id", mediaID)
		writer.WriteField("segment_index", segmentIndexStr)
		err = writer.Close()
		if err != nil {
			return "", err
		}

		// Make the request
		req, err := http.NewRequest("POST", mediaUploadUrl, body)
		if err != nil {
			return "", err
		}
		req.Header.Add("Content-Type", writer.FormDataContentType())
		log.Printf("Making Twitter APPEND request: \n")
		httpResp, err := signingClient.Do(req)
		if err != nil {
			return "", err
		}
		defer httpResp.Body.Close()
		// successful response is 2xx
		if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
			// read the response body
			body, err := ioutil.ReadAll(httpResp.Body)
			if err != nil {
				return "", err
			}
			return "", errors.New("Twitter returned non-2xx response for APPEND: " + strconv.Itoa(httpResp.StatusCode) + " " + string(body))
		}
		if segmentEnd == len(fileBytes) {
			break
		}
	}

	// Make FINALIZE request to Twitter
	req, err = http.NewRequest("POST", mediaUploadUrl+"?command=FINALIZE&media_id="+mediaID, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	httpResp, err = signingClient.Do(req)
	if err != nil {
		return "", err
	}
	defer httpResp.Body.Close()
	// successful response is 2xx
	if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		return "", errors.New("Twitter returned non-2xx status code for FINALIZE: " + strconv.Itoa(httpResp.StatusCode))
	}

	return mediaID, nil
}

func (m *MastodonCrossPost) postToTwitter(toot Toot) error {
	if !strings.Contains(toot.Content, "health bars and rockets") {
		return nil
	}
	// If there are images in the media attachments, save them to temporary files.
	// We will delete them after we have posted the tweet.
	var mediaFiles []string
	for _, media := range toot.MediaAttachments {
		resp, err := http.Get(media.URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		file, err := ioutil.TempFile("", "mastodon-cross-post")
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err := io.Copy(file, resp.Body); err != nil {
			return err
		}
		mediaFiles = append(mediaFiles, file.Name())
	}

	var mediaIDs []string

	for _, mediaFile := range mediaFiles {
		mediaID, err := m.uploadMediaToTwitter(mediaFile)
		if err != nil {
			return err
		}
		// Add the media id
		mediaIDs = append(mediaIDs, mediaID)
	}

	content := m.convertTootHTMLToText(toot.Content)
	if content == "" && len(mediaIDs) == 0 {
		log.Println("Toot empty, skipping")
		return nil
	}
	log.Println("Posting tweet: ", content)
	tweetToPost := PostTweetRequest{
		Text: content,
	}

	if len(mediaIDs) > 0 {
		tweetToPost.Media = &TweetMediaRequest{
			MediaIDs: mediaIDs,
		}
	}

	// If toot is a reply, add the original tweet ID to the tweet
	if toot.InReplyToID != "" {
		if tweetReply, ok := m.tootToTweetMap[toot.InReplyToID]; ok {
			tweetToPost.Reply = &PostTweetReplyRequest{
				InReplyToTweetID: tweetReply.tweetID,
			}
		}
	}

	jsonBody, err := json.Marshal(tweetToPost)
	if err != nil {
		return err
	}

	// Post the tweet
	req, err := http.NewRequest("POST", m.twitterPostTweetUrl, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	m.lock.RLock()
	req.Header.Set("Authorization", "Bearer "+m.twitterToken.AccessToken)
	m.lock.RUnlock()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("error posting to Twitter: %s", resp.Status)
	}

	var tweetResponse PostTweetResponse
	if err := json.NewDecoder(resp.Body).Decode(&tweetResponse); err != nil {
		return err
	}

	log.Printf("Saving %s as %s\n", toot.ID, tweetResponse.Data.ID)
	m.tootToTweetMap[toot.ID] = tootMapEntry{
		toot:    toot,
		tweetID: tweetResponse.Data.ID,
	}

	// Save last seen toot ID
	m.lastSeenTootID = toot.ID
	return nil
}

func (m *MastodonCrossPost) getTwitterToken(refresh bool) error {
	var body *TwitterOAuthTokenRequest
	if refresh {
		body = &TwitterOAuthTokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: m.twitterToken.RefreshToken,
		}
	} else {
		code := m.getTwitterOAuthCode()
		body = &TwitterOAuthTokenRequest{
			Code:         code,
			GrantType:    "authorization_code",
			RedirectUri:  m.redirectURI,
			CodeVerifier: "challenge",
		}
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", m.twitterOAuth2TokenUrl, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", getBasicAuthHeader(m.clientID, m.clientSecret))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Check status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error getting Twitter token: %s", resp.Status)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var tokenResponse TwitterOAuthTokenResponse
	err = json.Unmarshal(bodyBytes, &tokenResponse)
	if err != nil {
		return fmt.Errorf("error getting Twitter token: %s", err)
	}
	// Save token
	m.lock.Lock()
	m.twitterToken = &tokenResponse
	m.twitterTokenExpiry = time.Now().Add(time.Duration(m.twitterToken.ExpiresIn) * time.Second)
	m.lock.Unlock()
	log.Println("Twitter token expiry is", m.twitterTokenExpiry)
	return nil
}

func (m *MastodonCrossPost) getTwitterOAuthCode() string {
	clientID := m.clientID
	redirectUri := m.redirectURI
	// Create authorize url
	authURL := m.twitterAuthorizeUrl + "?client_id=" + clientID + "&redirect_uri=" + redirectUri + "&response_type=code" +
		"&scope=tweet.write%20offline.access%20users.read%20tweet.read&code_challenge=challenge&code_challenge_method=plain&state=state"
	log.Printf("Click on URL to authorize: %s\n", authURL)
	responseCh := make(chan authResponse)
	handler := func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		responseCh <- authResponse{code: code, state: state}
	}
	// Get listen port from redirectURI
	listenPort := strings.Split(m.redirectURI, ":")[2]
	s := &http.Server{
		Addr:    ":" + listenPort,
		Handler: http.HandlerFunc(handler),
	}

	// Start temporary server for the purpose of getting the OAuth code
	go func() {
		log.Println("Starting temporary server on port", listenPort)
		err := s.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	select {
	case response := <-responseCh:
		_ = s.Shutdown(context.Background())
		return response.code
	case <-time.After(30 * time.Second):
		_ = s.Shutdown(context.Background())
	}
	return ""
}

func (m *MastodonCrossPost) getLatestToots() ([]Toot, error) {
	url := m.baseURL + fmt.Sprintf("/api/v1/accounts/%s/statuses", m.accountID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var toots []Toot
	err = json.NewDecoder(resp.Body).Decode(&toots)
	if err != nil {
		return nil, err
	}
	return toots, nil
}

func getBasicAuthHeader(consumerKey, consumerSecret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(consumerKey+":"+consumerSecret))
}
