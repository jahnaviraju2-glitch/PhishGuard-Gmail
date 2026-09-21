from src.gmail_service import get_recent_emails


print("\n==============================")
print("PHISHGUARD AI - GMAIL TEST")
print("==============================\n")

try:
    emails = get_recent_emails(5)

    print(f"Found {len(emails)} emails\n")

    for i, email in enumerate(emails, 1):

        print(f"---------- EMAIL {i} ----------")
        print("FROM:", email["sender"])
        print("SUBJECT:", email["subject"])
        print("DATE:", email["date"])
        print("BODY:", email["body"][:300])
        print()

except Exception as e:
    print("\nERROR:")
    print(e)