# Static Lynx for Legacy Linux (v6): User guide

Lynx shows web pages as text and is driven entirely from the keyboard: arrow keys move between links, Enter follows one, and `q` quits. Press `?` inside Lynx at any time for help.

Related guides: [Program description](lynx_static_v6_program_description.md), [Administrator guide](lynx_static_v6_admin_guide.md).

## Start Lynx

```sh
lynx                          # opens the configured start page
lynx https://example.com      # opens a specific page
lynx file.html                # opens a local file
```

If your administrator installed it on the path, type `lynx`. Otherwise run the `lynx` launcher from the install folder, never `bin/lynx.bin`.

## Move around and open links

| Key | Action |
| --- | --- |
| Down arrow, Tab | Next link (or scroll down if there are no more) |
| Up arrow | Previous link (or scroll up) |
| Right arrow, Enter | Follow the highlighted link |
| Left arrow | Go back to the previous page |
| Space, `+`, Ctrl-F | Page down |
| `b`, `-`, Ctrl-B | Page up |
| Ctrl-A / Ctrl-E | Top / bottom of the page |
| `)` / `(` | Half a page down / up |
| `g` | Go to a URL you type |
| `G` | Edit the current page's URL, then go |
| `l` | List every link on the page |
| `m` | Return to the start page |
| `q` | Quit, with a confirmation. `Q` quits at once. |

A digit key jumps to a numbered link. Turn on link numbers with `-number_links` or in the options menu, type the number, then press Enter.

## Search a page

Press `/`, type the text and press Enter. Press `n` for the next match and `N` for the previous one. Searching ignores case unless you turn on case-sensitive search in the options menu.

## Back, history and bookmarks

| Key | Action |
| --- | --- |
| Left arrow | Back one page |
| Backspace | History page: every page on your path, to jump back to any of them |
| `V` | Visited Links page: everything seen this session |
| `a` | Add the current page or highlighted link to your bookmarks |
| `v` | View your bookmarks. Press `r` on one to remove it. |

Bookmarks are kept in `lynx_bookmarks.html` in your home folder, as plain HTML you can edit.

## Forms and text fields

Move to a field with the arrow keys and start typing. Tab or Down moves on, and Enter on a button submits. Press Ctrl-G to cancel typing in a field. Lynx can ask you to confirm before it resubmits a form after you go back.

## Cookies and privacy

By default Lynx asks before accepting each cookie, and forgets them when you quit. Press Ctrl-K to open the cookie jar, where you can delete cookies or change a site's setting. Pass `-cookies` to switch cookie handling off or on for one session. If you are leaving your terminal, press `_` to clear passwords Lynx has remembered for the session.

## Certificate warnings

Lynx checks every secure site against its bundled list of trusted authorities. If it shows an SSL error and asks whether to continue, the site's certificate could not be verified. Answer `n` unless you know exactly why, such as a test server you run yourself. Never continue on a banking, shopping or sign-in page.

## Save, print and view source

| Key | Action |
| --- | --- |
| `d` | Download the highlighted link |
| `p` | Print or save the page to a file, or mail it |
| `\` | Toggle between the rendered page and its HTML source |
| `=` | Show details about the page and the highlighted link |
| Ctrl-R | Reload the page |
| Ctrl-L | Redraw a garbled screen |

## Options menu

Press `o` to change settings for your account. They are saved to `~/.lynxrc`. The menu covers user mode, cookie and SSL prompting, keyboard style (vi keys use `h j k l`, Emacs keys use Ctrl-B/N/P/F), character set, colours and link appearance. Press `k` to see the complete key list.

## Command-line options

| Option | Effect |
| --- | --- |
| `-dump` | Print the page as plain text and exit |
| `-nolist` | With `-dump`, leave out the list of links at the end |
| `-width=N` | Line width for dumps (default 80) |
| `-source` | Print the page's HTML source and exit |
| `-number_links` | Number every link on screen |
| `-vikeys` / `-emacskeys` | Use vi or Emacs movement keys |
| `-nocolor` | Turn colours off |
| `-useragent=NAME` | Send a different User-Agent header |
| `-connect_timeout=N` / `-read_timeout=N` | Give up after N seconds |
| `-cookies` | Toggle cookie handling |
| `-accept_all_cookies` | Accept cookies without asking |
| `-term=TERM` | Use a different terminal type |
| `-display_charset=NAME` | Character set of your terminal, such as `utf-8` |
| `-cfg=FILE` | Use a different configuration file |
| `-version` | Show the Lynx, OpenSSL and ncurses versions |
| `-help` | List every option |

Examples:

```sh
lynx -dump -nolist https://example.com > page.txt        # page as text
lynx -source https://example.com/data.json > data.json   # raw download
lynx -display_charset=utf-8 -assume_charset=utf-8 page.html
```

## Offline help

The package includes Lynx's own manual. Open `share/lynx_help/lynx_help_main.html` in the install folder: `lynx file://localhost/opt/lynx-2.9.0-static-x86_64-musl/share/lynx_help/lynx_help_main.html` (adjust the folder to match your install).

## If something looks wrong

| Problem | What to do |
| --- | --- |
| Screen is garbled or the cursor is lost | Press Ctrl-L. If it persists, quit and start with `TERM=xterm lynx`. |
| Accented letters or symbols show as `?` | Start with `-display_charset=utf-8` and make sure your terminal uses UTF-8. |
| A secure site is refused | The certificate failed checking. Tell your administrator; do not bypass it. |
| A page loads nothing for a long time | Press `z` to stop the transfer, then try again. |
| A site needs JavaScript or images | Lynx cannot show them. Look for a text or mobile version of the site. |
