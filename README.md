# mythic_sync

[![Sponsored by SpecterOps](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fspecterops%2F.github%2Fmain%2Fconfig%2Fshield.json&style=flat)](https://github.com/specterops#ghostwriter)

[![Python Version](https://img.shields.io/badge/Python-3.10-brightgreen.svg)](.) [![License](https://img.shields.io/badge/License-BSD3-darkred.svg)](.) ![GitHub Release (Latest by Date)](https://img.shields.io/github/v/release/GhostManager/mythic_sync?label=Latest%20Release) ![GitHub Release Date](https://img.shields.io/github/release-date/ghostmanager/mythic_sync?label=Release%20Date&color=blue)

The `mythic_sync` utility connects to a [Mythic](https://github.com/its-a-feature/Mythic) C2 server (>=3.0.0+) to ingest events and post these events to the [Ghostwriter](https://github.com/GhostManager/Ghostwriter) (>=v3.0.1) GraphQL API to create real-time activity logs.

This tool automatically logs all new agent callbacks and every operator's Mythic commands, comments, and output into Ghostwriter so operators can focus more on technical execution and less on manual and tedious logging and reporting activities.

The current version of `mythic_sync` requires Mythic >=v3.0.0 and Ghostwriter >=v3.0.1.

## Usage

### Getting Started

To authenticate to your instances of Mythic and Ghostwriter, you will need this information handy:

* Ghostwriter URL
* Ghostwriter GraphQL API token
* Ghostwriter log ID
* Mythic credentials

#### Ghostwriter API Token & Activity Log

You can get your log's ID by opening the log's webpage and looking at the top of the page. You'll see "Oplog ID #" followed by a number. That's the ID number you need.

To generate an API token for your Ghostwriter instance, visit your user profile and click on the "Create" button in the "API Tokens" section.

The token must be attached to an account that has access to the project containing your target oplog. You can read more about the [authorization controls on the Ghostwriter wiki](https://www.ghostwriter.wiki/features/graphql-api/authorization).

### Execute via Mythic 3.0+ and `mythic-cli`

For the easiest experience with `mythic_sync`, install it via the `mythic-cli` tool. When installed this way, the `mythic_sync` service will become part of your Mythic deployment. You can then use `mythic-cli` to manage `mythic_sync` (just like Mythic) and the service will come up and go down alongside your other Mythic services.

On your Mythic server, run: `sudo ./mythic-cli mythic_sync install github https://github.com/GhostManager/mythic_sync`

Follow the prompts to configure `mythic_sync` with your Mythic and Ghostwriter server configuration.

You can get your Ghostwriter Oplog ID by visiting your log in your web browser and looking at the top of the page or the URL. A URL with `/oplog/12/entries` means your Oplog ID is `12`.

```bash
sudo ./mythic-cli mythic_sync install github https://github.com/GhostManager/mythic_sync
[*] Creating temporary directory
[*] Cloning https://github.com/GhostManager/mythic_sync
Cloning into '/opt/Mythic/tmp'...
Please enter your GhostWriter API Key: eyJ0eXAiO...
Please enter your GhostWriter URL: https://ghostwriter.domain.com
Please enter your GhostWriter OpLog ID: 12
Please enter your Mythic API Key (optional):
[+] Added mythic_sync to docker-compose
[+] Successfully installed mythic_sync!
[+] Successfully updated configuration in .env
```

### Execute via Stand Alone Docker

Alternatively, you can use Docker and `docker-compose` to run the `mythic_sync` container. Use this option if you'd prefer to run `mythic_sync` on a different server than your Mythic containers or don't want to use `mythic-cli` to manage the service.

After cloning repository, open the `settings.env` file and fill in the variables with appropriate values. The following is an example:

```text
MYTHIC_IP=10.10.1.100
MYTHIC_USERNAME=mythic_admin
MYTHIC_PASSWORD=SuperSecretPassword
GHOSTWRITER_API_KEY=eyJ0eXAiO...
GHOSTWRITER_URL=https://ghostwriter.mydomain.com
GHOSTWRITER_OPLOG_ID=12
```

Once the environment variables are set up, you can launch the service by using `docker-compose`:

``` bash
docker-compose up
```

### Verify Successful Start-Up

Open your Ghostwriter log and look for an initial entry. You should see something like the following:

    > Initial entry from mythic_sync at: <server_ip>. If you're seeing this then oplog syncing is working for this C2 server!

If so, you're all set! Otherwise, check the logs from the docker container for error messages. Fetch the logs with:

`sudo ./mythic-cli logs mythic_sync`

## Troubleshooting

Ensure the host where `mythic_sync` is running has network access to the Ghostwriter and Mythic servers.

`mythic_sync` uses an internal Redis database to sync what events have already been sent to Ghostwriter, avoiding duplicates.

If the `mythic_sync` service goes down, it is safe to stand it back up and avoid duplicates as long as nothing has forcefully stopped Mythic's Redis container.

## References

- [Mythic](https://github.com/its-a-feature/Mythic) - Multi-platform C2 Framework
- [Ghostwriter](https://github.com/GhostManager/Ghostwriter) - Engagement Management and Reporting Platform
- [Ghostwriter's Official Documentation - Operation Logging w/ Ghostwriter](https://ghostwriter.wiki/features/operation-logs) - Guidance on operation logging setup and usage with Ghostwriter
- [Blog - Updates to Ghostwriter: UI and Operation Logs](https://posts.specterops.io/updates-to-ghostwriter-ui-and-operation-logs-d6b3bc3d3fbd_) - Initial announcement of the operation logging features in Ghostwriter
