import asyncio
from playwright.async_api import async_playwright
import json

async def audit_site(name, url, cookies=None):
    print(f"\n--- Auditing {name} ({url}) ---")
    async with async_playwright() as p:
        browser_path = "/usr/bin/chromium-browser"
        browser = await p.chromium.launch(executable_path=browser_path, headless=True)
        context = await browser.new_context()

        if cookies:
            await context.add_cookies(cookies)

        page = await context.new_page()

        # Log console messages
        page.on("console", lambda msg: print(f"  [Console {msg.type}] {msg.text}"))

        try:
            await page.goto(url, wait_until="networkidle", timeout=60000)
            await asyncio.sleep(5) # Wait longer for React to mount

            report = {
                "url": url,
                "tabs": [],
                "sidebar_controls": [],
                "table_headers": [],
                "sub_tabs": []
            }

            # 1. Main Navigation Tabs
            tabs = await page.query_selector_all("nav a, .tab-btn")
            for tab in tabs:
                text = await tab.inner_text()
                if text.strip():
                    report["tabs"].append(text.strip())

            # 2. Sidebar Sorting/Filter Check
            sort_btns = await page.query_selector_all("button, .sort-btn")
            for b in sort_btns:
                text = await b.inner_text()
                if text.strip():
                    report["sidebar_controls"].append(text.strip())

            # 3. Table Headers
            headers = await page.query_selector_all("th")
            report["table_headers"] = [ (await h.inner_text()).strip() for h in headers if (await h.inner_text()).strip() ]

            # 4. Check for nested tabs
            sub_tabs = await page.query_selector_all("nav nav a, .psub-btn, .rsub-btn, .stab-btn")
            report["sub_tabs"] = [ (await t.inner_text()).strip() for t in sub_tabs if (await t.inner_text()).strip() ]

            print(json.dumps(report, indent=2))
            return report

        except Exception as e:
            print(f"Error auditing {name}: {e}")
        finally:
            await browser.close()

async def main():
    demo_url = "https://sudo-logger.unixkonsult.se/demo/"
    new_url  = "http://replay.192.168.2.163.nip.io/"

    # Audit Demo
    demo_report = await audit_site("Demo", demo_url)

    # Audit New (with cookie)
    cookie_value = "cQ06d06SkAVXxLXc-NncFjfRXDkE4fgRJ18NSHEPHARzkjShqWOKtWzs9zmH2XVi3ubT2e7DihgoF8Ru_geBoD5NfBnBhNz4tewMQorefPHOqxyrlHReS7G5yEzEb-vZUHjGOPFGUZ_UW3RHVAoJC_e4AnJLQR4vcmr37VkbaDgqeDkFfiekRjgXtM2c_2vypl8IpeV72b_eueILiOF0xftHbsLx1Lg|1781199250|9zgzsGTGD9D3OSTMMcHKnqqrePFSAQtu1WVHaApTLp0="
    new_cookies = [{
        "name": "_oauth2_replay",
        "value": cookie_value,
        "domain": "replay.192.168.2.163.nip.io",
        "path": "/"
    }]
    new_report = await audit_site("New React UI", new_url, new_cookies)

if __name__ == "__main__":
    asyncio.run(main())
