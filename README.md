# nio basic security module

A nio module providing basic security authentication


## Configuration

[security]

user in the system, where each entry is defined as: 
```
"[Username]": {"password": "[base64 encoded password]"} ("User": {"password": "VXNlcg=="})
```
or
```
"[Username]": {"password": "[bcypt hashed password]"} ("User": {"password": "$2b$12$pgfW7h9YEAkm5HafKuvT/uyChSMr9FgEFDxmM9uTZOSMJSvFUmiOW" })
```
- users=etc/users.json

user permissions in the system, where each entry is defined as:
```
[Username]: [dictionary of permissions] ("Admin": {".*": "rwx"})
```
- permissions=etc/permissions.json

## Dependencies

- bcrypt
