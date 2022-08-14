package cmd

import (
	"bufio"
	"log"
	"os"
	"strings"

	"github.com/mcartmell/mastodon-twitter-crosspost/internal/crosspost"
)

const (
	twitterOAuth2TokenUrl = "https://api.twitter.com/2/oauth2/token"
	twitterPostTweetUrl   = "https://api.twitter.com/2/tweets"
	twitterAuthorizeUrl   = "https://twitter.com/i/oauth2/authorize"
	twitterMediaUploadUrl = "https://upload.twitter.com/1.1/media/upload.json"
)

// Run runs the crosspost command.
func Run() {
	setEnvFromDotenvFile()

	m := crosspost.NewMastodonCrossPost(
		os.Getenv("MASTODON_URL"),
		os.Getenv("MASTODON_ACCOUNT_ID"),
		os.Getenv("TWITTER_OAUTH2_REDIRECT_URI"),
		os.Getenv("TWITTER_OAUTH2_CLIENT_ID"),
		os.Getenv("TWITTER_OAUTH2_CLIENT_SECRET"),
		os.Getenv("TWITTER_CONSUMER_KEY"),
		os.Getenv("TWITTER_CONSUMER_SECRET"),
		os.Getenv("TWITTER_ACCESS_TOKEN"),
		os.Getenv("TWITTER_ACCESS_TOKEN_SECRET"),
		twitterAuthorizeUrl,
		twitterOAuth2TokenUrl,
		twitterPostTweetUrl,
		twitterMediaUploadUrl,
	)
	m.CrossPostTweets()
}

// setEnvFromDotenvFile sets the environment variables from a .env file.
func setEnvFromDotenvFile() {
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		return
	}
	log.Println("Loading environment variables from .env file")
	file, err := os.Open(".env")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export") {
			line = line[7:]
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := parts[1]
		if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
			value = value[1 : len(value)-1]
		}
		os.Setenv(key, value)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
