package crosspost

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func getMockCrosspost() *MastodonCrossPost {
	return &MastodonCrossPost{
		tootToTweetMap: make(map[string]tootMapEntry),
	}
}

func getRandomPortIfAvailable() int {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	return port
}

func TestGetTwitterToken(t *testing.T) {
	m := getMockCrosspost()
	// Get a random available port
	port := getRandomPortIfAvailable()
	listenPort := port

	// Create a mock http server for the Twitter response for the OAuth2 token.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/oauth2/token" {
			w.Write([]byte(`{
				"access_token": "test_access_token",
				"token_type": "bearer",
				"expires_in": 3600
			}`))
		}
	}))
	m.twitterOAuth2TokenUrl = ts.URL + "/oauth2/token"
	m.twitterAuthorizeUrl = ts.URL + "/oauth2/authorize"
	m.redirectURI = "http://localhost:" + strconv.Itoa(listenPort)

	doneCh := make(chan struct{})
	go func() {
		err := m.getTwitterToken(false)
		if err != nil {
			t.Errorf("Error getting Twitter token: %v", err)
		}
		doneCh <- struct{}{}
	}()

	http.Get("http://localhost:" + strconv.Itoa(listenPort) + "/?code=test_code")
	<-doneCh

	if m.twitterToken.AccessToken != "test_access_token" {
		t.Errorf("Error getting Twitter token: incorrect access token")
	}
}

func TestGetLatestToots(t *testing.T) {
	m := getMockCrosspost()
	m.accountID = "test_account_id"
	mockToots := []Toot{
		{
			ID:                 "test_toot_id",
			InReplyToID:        "",
			InReplyToAccountID: "",
			Content:            "test_toot_content",
			CreatedAt:          time.Now(),
		},
		{
			ID:        "test_toot_id_2",
			Content:   "test_&#123;toot_content_2\n\n<p>test_toot_content_2_2</p>",
			CreatedAt: time.Now().Add(time.Hour * -1),
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		tootsJSONStr, err := json.Marshal(mockToots)
		if err != nil {
			t.Errorf("Error marshalling toots to JSON: %v", err)
		}

		if r.URL.Path == "/api/v1/accounts/test_account_id/statuses" {
			w.Write(tootsJSONStr)
		}
	}))
	m.baseURL = ts.URL

	toots, err := m.getLatestToots()
	if err != nil {
		t.Errorf("Error getting latest toots: %v", err)
	}
	if len(toots) != 2 {
		t.Errorf("Error getting latest toots: incorrect number of toots")
	}
	for i, toot := range toots {
		if toot.ID != mockToots[i].ID {
			t.Errorf("Error getting latest toots: incorrect toot ID")
		}
		if toot.Content != mockToots[i].Content {
			t.Errorf("Error getting latest toots: incorrect toot content")
		}
		if !toot.CreatedAt.Equal(mockToots[i].CreatedAt) {
			t.Errorf("Error getting latest toots: incorrect toot created at")
		}
	}
}

func TestPostToTwitter(t *testing.T) {
	m := getMockCrosspost()
	m.twitterToken = &TwitterOAuthTokenResponse{
		AccessToken: "test_access_token",
		TokenType:   "bearer",
		ExpiresIn:   3600,
	}
	mockToots := []Toot{
		{
			ID:          "test_toot_id",
			InReplyToID: "",

			InReplyToAccountID: "",
			Content:            "test_toot_content",
			CreatedAt:          time.Now(),
		},
		{
			ID:        "test_toot_id_2",
			Content:   "test_&#123;toot_content_2\n\n<p>test_toot_content_2_2</p>",
			CreatedAt: time.Now().Add(time.Hour * -1),
		},
	}

	tootsProcessed := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Unmarshal JSON request body
		var toot PostTweetRequest
		err := json.NewDecoder(r.Body).Decode(&toot)
		if err != nil {
			t.Errorf("Error unmarshalling JSON: %v", err)
		}
		// Check that the toot is correct
		expectedContent := m.convertTootHTMLToText(mockToots[tootsProcessed].Content)
		if toot.Text != expectedContent {
			t.Errorf("Error posting to Twitter: incorrect toot content: %v != %v", toot.Text, expectedContent)
		}

		tootsProcessed += 1
		w.WriteHeader(http.StatusCreated)
		resp := &PostTweetResponse{
			Data: PostTweetData{
				ID:   "test_toot_id",
				Text: toot.Text,
			},
		}
		respJSONStr, err := json.Marshal(resp)
		if err != nil {
			t.Errorf("Error marshalling response to JSON: %v", err)
		}
		w.Write(respJSONStr)

	}))
	m.twitterPostTweetUrl = ts.URL

	// Call postToTwitter for each mock toot
	for _, toot := range mockToots {
		err := m.postToTwitter(toot)
		if err != nil {
			t.Errorf("Error posting to Twitter: %v", err)
		}
	}
}
