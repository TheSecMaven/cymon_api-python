# Pull From the Cymon API with Whois Information from the X-Force Exchange API

This was created to allow for the ability to pull whois information in concurrence with the Cymon API information. Cymon does not currently have this option available. <br><br>

This works the same way as the main Cymon API only tool works. Generate a database with `python build_database.py` and after inserting API keys for ** Cymon and X-Force APIs** run `query_cymon_api_whois.py` with the same parameters as `query_cymon_api.py` but WHOIS information will be added to the database as well with this script.

