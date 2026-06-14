import asyncio
from playwright.async_api import async_playwright
import os

async def run_test(url):
    async with async_playwright() as p:
        browser_path = "/usr/bin/chromium-browser"
        print(f"Startar webbläsare från {browser_path}...")

        browser = await p.chromium.launch(executable_path=browser_path, headless=True)
        # Skapa en kontext för att kunna sätta cookies
        context = await browser.new_context()

        # Injektion av session-cookie från bilden
        cookie_value = "cQ06d06SkAVXxLXc-NncFjfRXDkE4fgRJ18NSHEPHARzkjShqWOKtWzs9zmH2XVi3ubT2e7DihgoF8Ru_geBoD5NfBnBhNz4tewMQorefPHOqxyrlHReS7G5yEzEb-vZUHjGOPFGUZ_UW3RHVAoJC_e4AnJLQR4vcmr37VkbaDgqeDkFfiekRjgXtM2c_2vypl8IpeV72b_eueILiOF0xftHbsLx1Lg|1781199250|9zgzsGTGD9D3OSTMMcHKnqqrePFSAQtu1WVHaApTLp0="

        await context.add_cookies([{
            "name": "_oauth2_replay",
            "value": cookie_value,
            "domain": "replay.192.168.2.163.nip.io",
            "path": "/"
        }])

        page = await context.new_page()

        logs = []
        page.on("console", lambda msg: logs.append(f"[{msg.type}] {msg.text}"))

        print(f"Navigerar till {url} med session-cookie...")
        try:
            await page.goto(url, wait_until="networkidle", timeout=60000)
            await asyncio.sleep(5) # Vänta på rendering

            await page.screenshot(path="replay_auth_check.png", full_page=True)
            print("Skärmbild sparad till replay_auth_check.png")

            title = await page.title()
            print(f"Sidans titel: {title}")

            content = await page.content()
            print(f"Längd på hämtad HTML: {len(content)} bytes")

            # Kolla om vi ser xterm nu
            xterm = await page.query_selector(".xterm")
            if xterm:
                print("SUCCESS: Hittade xterm.js-terminalen! Vi är inloggade.")
            else:
                print("Kunde fortfarande inte hitta .xterm. Vi kanske skickades tillbaka till login?")

            print("\n--- Konsol-loggar ---")
            for log in logs:
                print(log)

        except Exception as e:
            print(f"Fel: {e}")
        finally:
            await browser.close()

if __name__ == "__main__":
    target_url = "http://replay.192.168.2.163.nip.io/"
    asyncio.run(run_test(target_url))
