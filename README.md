### Fixed the double Telegram messages issue:

- Modified the sendTelegram function to just send the message and return the response
- Changed how it's called in add_to_tik to sendTelegram(...) instead of requests.get(sendTelegram(...))
- Removed comments
- Added error handling for the UPTIME_BOOKMARK file

### Simplified code by:

- Removing unnecessary sleep() call in the ignore_list check
- Simplifying the cmnt variable assignment in add_saved_lists
- Improving error messages to be more consistent
- Streamlining the return values and flow

### Fixed potential bugs:

- Added proper file existence checking for the saved lists
