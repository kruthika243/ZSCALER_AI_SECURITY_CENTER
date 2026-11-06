
from core.google_safe_browsing import check_google_safe_browsing

test_url = "https://example.com"

print("\nZSCALER GOOGLE SAFE BROWSING TEST")
print("-" * 45)

result = check_google_safe_browsing(test_url)

print("Test URL:", test_url)
print("Status:", result["status"])
print("Message:", result["message"])

if result["matches"]:
    print("\nThreat matches:")

    for match in result["matches"]:
        print(match)

print("-" * 45)
