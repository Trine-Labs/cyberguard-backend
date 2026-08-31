import requests

urls = [
    "https://cyberguardsystem.online/auth/login",
    "https://cyberguardsystem.online/api/v1/m365/permissions",
    "https://cyberguardsystem.online/api/v1/auth/login",
    "https://cyberguardsystem.online/onboarding/password",
    "https://cyberguardsystem.online/onboarding/scope",
    "https://cyberguardsystem.online/onboarding/m365",
    "https://cyberguardsystem.online/onboarding/status",
]

for url in urls:
    try:
        r = requests.get(url, timeout=10, verify=False)
        print(f"{url} -> Status {r.status_code}, Length: {len(r.text)}")
    except Exception as e:
        print(f"{url} -> Error: {e}")
