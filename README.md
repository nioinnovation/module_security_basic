# nio basic security module

A nio module providing basic security authentication


## Configuration

[security]

user in the system, where each entry is defined as "[Username]": {"password": "[base64 encoded password]"} ("User": {"password": "VXNlcg=="})
- users=etc/users.json

user permissions in the system, where each entry is defined as [Username]: [list of permissions] ("Admin": ["*"])
- permissions=etc/permissions.json

## Dependencies

- None
