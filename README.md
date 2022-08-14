# Mastodon-Twitter-Crosspost

A lightweight program to crosspost from Mastodon to Twitter, suitable for self-hosting. It will poll the Mastodon instance every minute for new posts and post them to Twitter.

*WARNING* This is a work in progress with only basic functionality for cross-posting tweets and your own replies.

## Getting Started

### Prerequisites

- A [Mastodon](https://mastodon.social/) account
- A [Twitter](https://twitter.com/) account
- A [Twitter developer account](https://developer.twitter.com/) with OAuth 2.0 credentials

Note that Twitter API v1.1 and OAuth 1.0 are not supported.

### Installing

```
go install github.com/mcartmell/mastodon-twitter-crosspost@latest
```

Create a `.env` file with your credentials, for example:

```
MASTODON_URL=https://mastodon.example.com
MASTODON_ACCOUNT_ID=123456789
TWITTER_OAUTH2_REDIRECT_URI=http://localhost:8888
TWITTER_OAUTH2_CLIENT_ID=123456789
TWITTER_OAUTH2_CLIENT_SECRET=123456789
```

Run the program:

    mastodon-twitter-crosspost

The program will output a link to authorize API access to your Twitter account. Follow the instructions to complete the authorization.

## Features

- Crossposts from Mastodon to Twitter
- Supports crossposting own threads
- Supports images

## TODO

This is a work in progress with many missing features:

- Support for videos
- Support for content warnings

## Deployment

There is a [Dockerfile](Dockerfile) included for deployment, intended for self-hosting with minimal memory usage.

## License

This project is licensed under the [MIT license](LICENSE), see the [LICENSE](LICENSE) file for details.
