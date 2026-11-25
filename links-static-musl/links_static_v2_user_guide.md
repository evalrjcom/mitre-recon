# Static Links for Legacy Linux (v2): User guide

Links is a text-mode web browser. You drive it from the keyboard in a terminal. Overview: [Program description](links_static_v2_program_description.md). Install and settings: [Administrator guide](links_static_v2_admin_guide.md).

## 1. Starting

```sh
links-color https://www.example.org      # open a page
links-color                               # start empty, then press g to type an address
links-color -dump https://example.org     # print the page as plain text and exit
```

Start it with `links-color` (or the `links` link your administrator set up to it), not the bare `links` file, or secure (HTTPS) sites may report a certificate error.

## 2. The screen

The page fills the screen. Links are highlighted, and the selected link is brighter. The bottom line shows status and the address of the selected link. Press `ESC` for the menu bar.

## 3. Everyday keys

| Key | Action |
| --- | --- |
| Up / Down | Select the previous / next link |
| Right arrow or Enter | Follow the selected link |
| Left arrow, or `z` | Go back |
| `x` (or `'`) | Go forward |
| `p` / `l` | Scroll up / down a line |
| Page Up / Page Down | Scroll by page |
| `[` / `]` | Scroll left / right |
| `H` / `L` | Select the top / bottom link on screen |
| `g` | Go to a URL (type it, press Enter) |
| `G` | Go to a URL, starting from the current one for editing |
| Ctrl-G | Go to a URL starting from the selected link's address |
| `/` | Search forward in the page |
| `?` | Search backward |
| `n` / `N` | Next / previous search match |
| Ctrl-R | Reload |
| `s` | Bookmark manager |
| `\` | Switch between the formatted page and its HTML source |
| `=` | Document information, including connection details |
| `\|` | Show the server's HTTP headers |
| `F1` | Full key list |
| `ESC` or `F9` | Open the menu bar |
| `F10` | Open the File menu |
| Ctrl-C, `q` or `Q` | Quit (may ask for confirmation) |
| `a`, `w` | Move the cursor to the status line or title |
| `*` | Toggle image display (no effect in this text-mode build) |
| Tab | Switch frames |

In a text box, type to enter text; Ctrl-B, Ctrl-X, Ctrl-V and Ctrl-K copy, cut, paste, and cut a line. Down or Tab moves between form fields; Enter submits.

## 4. Menus

Press `ESC`, then use the arrows and Enter (or the highlighted letter). The bar has six entries: **File**, **View**, **Link**, **Downloads**, **Setup**, **Help**.

- **File:** go to URL, history, reload, bookmarks, save, memory info, quit.
- **View:** find next/previous, toggle HTML source, document and header info, HTML options.
- **Link:** actions on the selected link, such as following or downloading it.
- **Downloads:** list and manage running downloads.
- **Setup:** language, terminal options, network and SSL options, save options.
- **Help:** key list (`F1`), licence, about.

## 5. Getting good colour

1. Check `echo $TERM`. `links-color` sets `xterm-256color` for you when the terminal reports plain `xterm` or `linux`.
2. In Links: `ESC` > **Setup** > **Terminal options** > set the colour mode to **256 colors**.
3. Tick the UTF-8 option if your terminal uses UTF-8, and pick the matching charset.
4. `ESC` > **Setup** > **Save options** so it sticks.
5. Page colours (text, links, background) can be tuned in **Setup** > **HTML options**.

If box lines show as letters (`qqqq`), switch the frames or pseudographics terminal option on or off until borders look right.

## 6. Bookmarks, history, downloads

- Press `s` to open the bookmark manager, then choose Add to save the current page. (`a` is not the bookmark key.)
- File > History lists visited pages.
- To download, select a link and use the Link menu's download option, or open a file link Links cannot display: it offers to save it. The Downloads menu shows progress. Files go to the directory Links was started in, unless your administrator set a download directory.

## 7. Forms and logins

Select a form field and press Enter to edit it, type, then select the button and press Enter to submit. Passwords show as asterisks. Links cannot run JavaScript, so many modern logins, search boxes and menus will not work. Look for a plain or "lite" version of the site.

## 8. Security tips

- A normal HTTPS visit shows no warning. If you get **Invalid certificate**, stop and do not enter passwords. Check that the computer's date is right and tell your administrator.
- Press `=` on a secure page to see the connection details.
- On a shared machine, ask your administrator whether cookies and history are saved to disk.

## 9. Useful command-line options

| Option | Meaning |
| --- | --- |
| `-dump URL` | Print the page as text and exit |
| `-width N` | Format `-dump` output to N columns |
| `-source URL` | Print raw page data, unformatted |
| `-download-dir DIR` | Where downloads are saved |
| `-no-connect` | Open a separate instance instead of joining a running one |
| `-anonymous` | Restricted mode: no local files, no downloads |
| `-help` | List every option |

## 10. Quick troubleshooting

| What you see | What to do |
| --- | --- |
| Page opens as garbled text | Press `\` to toggle HTML and plain, or check Setup > Terminal options (charset) |
| "Invalid certificate" | Start with `links-color`; check the clock; ask your administrator |
| Only black-and-white or 16 colours | Set the colour mode to 256 colors (section 5) |
| Page is empty or asks you to enable JavaScript | Links does not support JavaScript; try another page |
| Cannot connect | Check the network and the proxy settings (Setup > Network options) |
| Stuck on a slow page | Go back with the Left arrow or `z`, or quit with Ctrl-C |
