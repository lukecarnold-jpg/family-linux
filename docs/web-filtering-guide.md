# Web filtering: a step-by-step guide for parents

Written for: parents with no IT background. You do not need to know how the internet works to follow this guide.

## Before you start

- You need the **parent password**. It is the password you set when you installed Family Linux.
- Web filtering works on **this computer only**, and only for **child accounts**. It cannot filter a phone, a tablet, or a child's own device.
- You can make changes in two ways:
  - **The Family Controls app** (recommended). Open it from the app menu, and enter your password when asked.
  - **The Terminal.** Type `sudo family-ctl ...` followed by the command, and enter your password when asked. The steps below show both.

## What the filter does

1. **Blocks sites from a list.** Adult and gambling sites, the Omegle and Chatroulette chat sites, and TikTok are blocked by default.
2. **Allows sites you choose.** Some educational sites are always allowed by default: Wikipedia, Khan Academy, Scratch, NASA and PBS Kids.
3. **Filters search results.** SafeSearch is turned on for Google, Bing, DuckDuckGo and YouTube.
4. **Asks you when a site is blocked.** If your child tries a blocked site, it appears in **Website requests** for you to decide.
5. **Turns off some browser features** that could get around the filter, such as private (incognito) windows, developer tools and extra browser add-ons.

## Step 1: Check the current settings

**In the Family Controls app:**

1. Open **Family Controls** and enter your password if asked.
2. Click your child's name in the left-hand list.
3. Look at the **Websites** section. It shows the sites that are blocked and allowed for that child.

**In the Terminal:**

```
sudo family-ctl web status
```

This shows the DNS provider, SafeSearch, incognito and developer-tools settings, and the blocked sites.

## Step 2: Block a website for your child

**In the app:**

1. Open the child's page, then find **Websites**.
2. In **Block a website**, type the site, for example `example.com`.
3. Press the **Apply** button (the tick at the end of the box).

**In the Terminal:**

```
sudo family-ctl web block example.com --child kid
```

Replace `kid` with your child's username. Leave out `--child kid` to block the site for every child.

## Step 3: Always allow a website

Use this for a site that is blocked by default, or one you want to be sure is available.

**In the app:** type the site into **Always allow a website** and press **Apply**.

**In the Terminal:**

```
sudo family-ctl web allow example.com --child kid
```

## Step 4: Cover all the pages on a site

To cover every part of a site, put `*.` in front of the name:

- `*.example.com` covers `www.example.com`, `news.example.com`, and any other part of it.
- `example.com` covers only that exact address.

## Step 5: Answer a website request

When your child tries a blocked site, it appears in **Website requests**.

1. Open **Family Controls**.
2. Click **Website requests** in the left-hand list.
3. For each request, choose one:
   - **Allow.** The site is allowed for that child only.
   - **Keep blocked.** The site stays blocked. The request is removed from the list.

In the Terminal:

```
sudo family-ctl web requests
sudo family-ctl web approve kid example.com
sudo family-ctl web deny kid example.com
```

## Step 6: Remove a rule

If you change your mind about a site, remove the rule. The site goes back to the default behaviour.

**In the app:** open the site's rule in the **Websites** section and remove it.

**In the Terminal:**

```
sudo family-ctl web remove example.com --child kid
```

## Step 7: Understand the browser settings

**SafeSearch** is on for your children in every browser. Search results from Google, Bing, DuckDuckGo and YouTube are filtered for explicit content. The children's web filter does this itself, so it works whichever DNS provider you use.

The settings below apply to **every user on this computer**, including you. Web browsers read one settings file for the whole computer, so they cannot be set for one person only:

- **Private (incognito) windows** are turned off.
- **Developer tools** are turned off.
- **Extra browser add-ons** cannot be installed.

Your child cannot change these settings, because they need your password to do so.

## Step 8: Know which DNS provider is in use

The DNS provider is the service that decides which sites your computer is allowed to reach. Each child uses the provider set for them; the default is CleanBrowsing Family. The options are:

| Provider | What it does |
|---|---|
| CleanBrowsing Family (default) | Blocks adult content and phishing sites, and enforces SafeSearch |
| Cloudflare Family | Blocks malware and adult content |
| AdGuard Family | Family protection filter and SafeSearch |
| OpenDNS FamilyShield | Default family protection |

There is no button to change the provider after installation yet. Check which one is in use with `sudo family-ctl web status`.

## Step 9: Check that the filter is working

1. Open a web browser while logged in as your child.
2. Go to a site you have blocked, for example `example.com`.
3. The site should not load. You should see it appear under **Website requests** in the app.
4. Run the built-in check:

```
sudo family-ctl verify
```

Look for any line marked **FAIL** that mentions DNS or web. If you see one, ask for help before relying on the filter.

## Keep the computer itself locked

Family Linux protects your children's accounts. Someone sitting at the computer could still start it from a USB stick and get around everything. Two settings on the computer stop that:

1. **Set a password for the computer's start-up settings** (called the BIOS or UEFI setup). How you get there depends on the make: usually a key such as F2, F10, F12 or Delete pressed straight after switching on. Look for "Supervisor password" or "Administrator password", and keep it somewhere safe.
2. **Turn off starting from USB sticks and other disks** in the same settings, or put the computer's own disk first and lock the order with that password.

Family Linux already asks for your name and password before anyone can change how Linux starts (the boot menu). That password is the parent password you chose when the computer was set up. If you change your password later, the boot menu keeps the original one.

## Things to expect

- **Some sites may not load for your child**, even when they are allowed. Some sites use a newer privacy feature, called Encrypted Client Hello, which the filter refuses for children so that it can check the site name. If a site will not load, that is the most likely reason. Allowing the site does not fix this.
- **Secure DNS and the newer web protocol (QUIC) are blocked for children.** Browsers fall back to normal web connections, so most sites still work.
- **The filter does not stop your child from using a phone or tablet**, or a computer that is not running Family Linux.
- **Children cannot use a terminal or install software without your password**, so they cannot turn the filter off.

## Other web browsers

The filter works the same way whichever browser your child uses. It does not live inside the browser: it checks every connection your child's account makes. A browser you install later is filtered from the moment it is installed.

Family Linux also switches on its browser settings in these browsers: private and guest windows off, SafeSearch on, YouTube restricted, developer tools off, the browser's own "secure DNS" off, and the proxy setting locked (a proxy could carry sites past the filter).

| Browser | Filter applies | Browser settings applied |
|---|---|---|
| Google Chrome | Yes | Yes, checked on a Family Linux computer |
| Firefox (installed with Family Linux) | Yes | Yes, checked on a Family Linux computer |
| Chromium (from Discover) | Yes | Yes, checked on a Family Linux computer |
| Microsoft Edge, Brave from Brave's own website | Yes | Should be, but not yet checked on a Family Linux computer |
| Falkon (from Discover) | Yes, checked on a Family Linux computer | No |
| Any other browser | Yes | No |

### Browsers from Discover

These are the browsers in Debian's own software, as found by a test on a Family Linux computer. A browser you install does not appear in your children's menus until you turn it on in Family Controls under Apps (Chromium and Chrome are already on for 10 and over).

- **Chromium** works. Your child may see a message saying an extension could not be loaded when Chromium starts. It is harmless: Family Linux stops browsers from loading extensions for children. Close the message.
- **Falkon** works, and the filter applies, including SafeSearch. Family Linux cannot switch on its other browser settings in Falkon (private windows, for example). Use Chrome, Firefox or Chromium if that matters to you.
- **Konqueror** is installed with KDE but hidden from the menus by Debian.

> **Please note: Falkon and Konqueror.** Family Linux cannot lock the settings in these two browsers. A child who knows how could set either one to send its traffic through a "proxy" (a go-between computer on the internet), and the websites they visit that way would not be checked by the filter, and would not get SafeSearch. If you want the filter to cover everything, do not turn these two browsers on for your children in Family Controls. Use Chrome, Firefox or Chromium instead.
- **GNOME Web (Epiphany)** and other small browsers built on the same engine (Luakit, surf, vimb) do not start for children. Their own safety sandbox clashes with Family Linux's. Nothing gets past the filter; the browser just closes. Use another browser.

### Installing Google Chrome

Google Chrome is the most widely used browser. To install it:

1. Sign in with your own (parent) account.
2. In Firefox, go to google.com/chrome and download Chrome. Choose the Debian/Ubuntu (.deb) download. It is saved in your Downloads folder.
3. Open Konsole (press Ctrl+Alt+T), type this line, press Enter, and enter your password when asked:

   ```
   sudo apt install ~/Downloads/google-chrome-stable_current_*.deb
   ```

Chrome adds Google's software source to the computer, so Chrome updates appear with the computer's other updates in Discover. The automatic security updates cover Debian's own software only, so install those updates from Discover now and then.

Chrome appears in your children's menus straight away for the 10 to 13 and 14 and over age settings. For a child under 10, turn it on in Family Controls under Apps. When your child opens Chrome, it shows "Your device is managed by your organization". This is expected: it is how Family Linux applies the browser settings.

### If a browser shows nothing at all

If a browser shows nothing at all for your child, even allowed sites, it is probably using its own "secure DNS" setting. The filter refuses those connections on purpose, so nothing gets around it. Turn off secure DNS in that browser's settings, or use Chrome or Firefox instead. To check, run this and look for "not returned by an allowed lookup":

```
sudo journalctl -u family-dnsd --since "10 min ago" | grep refuse
```

## Words used in this guide

- **Domain:** the address of a site, such as `example.com`.
- **DNS:** the internet's address book. It turns a site name into the place the computer connects to. The filter checks this step.
- **Wildcard:** the `*.` at the start of a name, which covers all parts of a site.
- **SafeSearch:** a search setting that hides explicit results.
- **Incognito (private) window:** a browser window that does not keep a history. Turned off here.
