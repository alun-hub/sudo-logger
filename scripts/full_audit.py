# Use token: _oauth2_replay cQ06d06SkAVXxLXc-NncFJfRXDkE4fgRJ18NSHEPHARzkjShqWOktWzs9zmH2XViI3ubT2e7DihgoF8Ru_geBoD5NfBnBhNz4tewMQorefPHOqxyrlHReS7G5yEzEb-vZUHjGOPFGUZ_UW3RHVAoJC_e4AnJLQR4vcmr37VkbaDgqeDkFfiekRJgXtM2c_2vypl8IpeV72b_eueIlIOF0xftHbsLx1Lg|1781199250|9zgzsGTGD9D3OSTMMcHKnqgrePFSAQtu1WVHaApTLp0=
import asyncio
from playwright.async_api import async_playwright
import json
import os

# Configuration
DEMO_URL = "https://sudo-logger.unixkonsult.se/demo/"
NEW_URL = "http://192.168.2.163:30080/" # Direct NodePort access to bypass OAuth2 proxy

async def explore(page, name_prefix):
    # Get all clickable navigation elements
    report = {}

    # 1. Main Tabs
    main_tabs = await page.query_selector_all("header nav a, .tab-btn")
    tab_names = []
    for tab in main_tabs:
        text = (await tab.inner_text()).strip()
        if text: tab_names.append(text)

    report["main_tabs"] = tab_names

    # 2. Map every tab's sub-content
    for tab_name in tab_names:
        print(f"  Exploring Tab: {tab_name}")
        # Click the tab
        try:
            tab_btn = page.get_by_text(tab_name, exact=True).first
            await tab_btn.click()
            await page.wait_for_load_state("networkidle")
            await asyncio.sleep(1)

            # Check for sub-tabs
            sub_tabs = await page.query_selector_all("nav nav a, .psub-btn, .stab-btn, .opa-subbtn, .rsub-btn")
            sub_tab_names = []
            for st in sub_tabs:
                st_text = (await st.inner_text()).strip()
                if st_text: sub_tab_names.append(st_text)

            report[f"tab_{tab_name}"] = {
                "sub_tabs": sub_tab_names,
                "buttons": [ (await b.inner_text()).strip() for b in await page.query_selector_all("button") if (await b.inner_text()).strip() ],
                "inputs": [ await i.get_attribute("placeholder") or await i.get_attribute("id") or await i.get_attribute("name") for i in await page.query_selector_all("input, select, textarea") ]
            }

            # If there are sub-tabs, explore them too
            for st_name in sub_tab_names:
                print(f"    Exploring Sub-Tab: {st_name}")
                try:
                    st_btn = page.get_by_text(st_name, exact=True).first
                    await st_btn.click()
                    await page.wait_for_load_state("networkidle")
                    await asyncio.sleep(0.5)
                    report[f"tab_{tab_name}"][f"sub_{st_name}"] = {
                        "buttons": [ (await b.inner_text()).strip() for b in await page.query_selector_all("button") if (await b.inner_text()).strip() ],
                        "inputs": [ await i.get_attribute("placeholder") or await i.get_attribute("id") or await i.get_attribute("name") for i in await page.query_selector_all("input, select, textarea") ]
                    }
                except: pass
        except Exception as e:
            print(f"    Failed to explore {tab_name}: {e}")

    return report

async def main():
    async with async_playwright() as p:
        browser_path = "/usr/bin/chromium-browser"
        browser = await p.chromium.launch(executable_path=browser_path, headless=True)

        # 1. Audit Demo
        print("\n--- AUDITING DEMO SITE ---")
        context_demo = await browser.new_context()
        page_demo = await context_demo.new_page()
        await page_demo.goto(DEMO_URL, wait_until="networkidle")
        demo_report = await explore(page_demo, "demo")
        with open("demo_audit.json", "w") as f:
            json.dump(demo_report, f, indent=2)

        # 2. Audit New UI
        print("\n--- AUDITING NEW REACT UI ---")
        context_new = await browser.new_context()
        page_new = await context_new.new_page()

        # Log all console messages for debugging
        page_new.on("console", lambda msg: print(f"  [New UI Console] {msg.type}: {msg.text}"))

        try:
            await page_new.goto(NEW_URL, wait_until="networkidle")
            new_report = await explore(page_new, "new")
            with open("new_audit.json", "w") as f:
                json.dump(new_report, f, indent=2)
        except Exception as e:
            print(f"Error auditing New UI: {e}")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
