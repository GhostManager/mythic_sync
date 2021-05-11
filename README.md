# mythic_sync

mythic_sync is a standalone tool that will connect to a [Mythic](https://github.com/its-a-feature/Mythic) C2 server to ingest command events and will then post them to the [Ghostwriter](https://github.com/GhostManager/Ghostwriter) Operation Log (oplog) API.

This enables automatic logging of every operator's Mythic commands, comments, and output into Ghostwriter so operators can focus more on technical execution and less on manual and tedious logging and reporting activities.

## Usage
### Execute w/ Docker (Option 1)

0. After checking out the repository, open the `settings.env` file and fill out the variables with appropriate values. The following is an example:

``` text
MYTHIC_IP=10.10.1.100
MYTHIC_USERNAME=apfell_user
MYTHIC_PASSWORD=SuperSecretPassword
GHOSTWRITER_API_KEY=f7D2nMPz.v8V5ioCNsSSoO19wNnBZsDhhZNmzzwNE
GHOSTWRITER_URL=https://ghostwriter.mydomain.com
GHOSTWRITER_OPLOG_ID=123
REDIS_HOSTNAME=redis
```

1. Once the environment variables are setup, you can launch the service by using docker-compose:

``` bash
docker-compose up
```

### Execute w/out Docker (Option 2)

0. After checking out the repository, open the `settings.sh` file and fill out the variables with appropriate values.

1. Install python virtual environments for python3 and redis

``` bash
apt install python3-venv redis
```

2. Create a new tmux session and virtual environment for mythic_sync and install required modules

``` bash
tmux
python3 -m venv .
source bin/activate
pip install -r requirements.txt
```

3. Set the environment variables and then run `sync.py` (ideally in a named Tmux session, `tmux new -s mythic_sync`)

``` bash
source ./settings.sh
python sync.py
```

### Verify Successful Start Up

1. Verify an initial entry in the target Ghostwriter's oplog was created. You should see something like the following:

    > Initial entry from mythic_sync at: <server_ip>. If you're seeing this then oplog syncing is working for this C2 server!

2. If so, you're all set! Otherwise, see "Troubleshooting"

## Troubleshooting

Ensure the host where mythic_sync is running has network access to the Ghostwriter and Mythic servers.

mythic_sync uses an internal redis database to sync what events have already been sent to Ghostwriter, avoiding duplicates. If you want to re-sync, you will need to delete the volume and run it again.

If the mythic_sync service goes down, it is safe to stand it back up and avoid duplicates as long as the redis container wasn't force killed.

## References

- [Mythic](https://github.com/its-a-feature/Mythic) - Multi-platform C2 Framework
- [Ghostwriter](https://github.com/GhostManager/Ghostwriter) - Engagement Management and Reporting Platform
- [Ghostwriter's Official Documentation - Operation Logging w/ Ghostwriter](https://ghostwriter.wiki/features/operation-logs) - Guidance on operation logging setup and usage with Ghostwriter
- [Blog - Updates to Ghostwriter: UI and Operation Logs](https://posts.specterops.io/updates-to-ghostwriter-ui-and-operation-logs-d6b3bc3d3fbd_) - Initial announcement of the operation logging features in Ghostwriter
