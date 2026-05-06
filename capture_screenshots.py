import asyncio
from playwright.async_api import async_playwright
import os
import requests

async def main():
    os.makedirs("report_images_light", exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        # Using a context with light color scheme
        context = await browser.new_context(viewport={"width": 1600, "height": 1200}, color_scheme="light")
        page = await context.new_page()
        
        await page.goto("http://localhost:8501/?theme=light")
        # Wait for Streamlit to load
        await page.wait_for_selector("text=Honeypot Log Storyteller", timeout=15000)
        await page.wait_for_timeout(2000)

        # 1. Dashboard Log Upload Interface
        await page.screenshot(path="report_images_light/Fig 3.2 Sprint I - Dashboard Log Upload Interface.png")

        # Upload file
        file_input = page.locator('input[type="file"]')
        await file_input.set_input_files("tests/sample_cowrie.json")
        
        # Click Process Logs
        await page.click("text=Process Logs")
        await page.wait_for_timeout(1000)
        
        # 6. Processing Status Flow
        await page.screenshot(path="report_images_light/Fig 6.1 Results - End-to-End Pipeline Validation Processing Status Flow.png")

        # Wait for the backend to finish processing via API
        print("Waiting for session to appear in backend...")
        sid = None
        for _ in range(60):
            try:
                resp = requests.get("http://localhost:8000/status/sessions/list")
                if resp.status_code == 200 and resp.json():
                    sid = resp.json()[0]["session_id"]
                    break
            except Exception:
                pass
            await asyncio.sleep(2)
            
        if not sid:
            print("Session not found in time!")
            return
            
        print(f"Found session {sid}. Waiting for analyzer to finish...")
        for _ in range(60):
            try:
                resp = requests.get(f"http://localhost:8000/report/{sid}")
                if resp.status_code == 200:
                    data = resp.json()
                    # Check if the profile is populated
                    if data.get("profile") and data["profile"].get("skill_level", "Unknown") != "Unknown":
                        print("Analysis completed and populated!")
                        break
            except Exception:
                pass
            await asyncio.sleep(2)

        # Now refresh Streamlit
        await page.click("text=Refresh Sessions")
        await page.wait_for_timeout(2000)
        
        # Wait for "Analysis Complete!" to appear
        await page.wait_for_selector("text=Analysis Complete!", timeout=15000)
        # Extra wait to ensure charts render and elements populate
        await page.wait_for_timeout(3000)

        # 2. Session Analysis View: Attacker Profile Card
        await page.evaluate("window.scrollTo(0, 0)")
        await page.wait_for_timeout(1000)
        await page.screenshot(path="report_images_light/Fig 3.3 Sprint II - Session Analysis View Attacker Profile Card.png")

        # 3. AI-Generated Attack Narrative Display
        await page.locator("text=📜 AI Narrative").scroll_into_view_if_needed()
        await page.wait_for_timeout(1000)
        await page.screenshot(path="report_images_light/Fig 3.4 Sprint II - AI-Generated Attack Narrative Display.png")

        # Wait longer for Plotly iframe to render
        print("Waiting 10 seconds for Plotly heatmap to fully render...")
        await page.wait_for_timeout(10000)

        # 4. ATT&CK Heatmap Visualization and Narrative Panel
        await page.locator("text=🎯 MITRE ATT&CK Enterprise Matrix").scroll_into_view_if_needed()
        await page.wait_for_timeout(2000)
        await page.screenshot(path="report_images_light/Fig 3.5 Sprint III - ATT&CK Heatmap Visualization and Narrative Panel.png")
        await page.screenshot(path="report_images_light/Fig 6.2 Results - MITRE ATT&CK Attack Progression Coverage Heatmap.png")

        # 5. Detected Techniques Table with Export Intelligence Panel
        await page.locator("text=💾 Export Intelligence").scroll_into_view_if_needed()
        await page.wait_for_timeout(1000)
        await page.screenshot(path="report_images_light/Fig 3.6 Sprint III - Detected Techniques Table with Export Intelligence Panel.png")

        await browser.close()

asyncio.run(main())
