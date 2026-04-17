from typing import Optional, List
from imap_tools import MailMessage
import re
from bs4 import BeautifulSoup

URL_ATTRS = {"href", "src", "action", "data", "poster"}

class Extractor:
    """A utility class for extracting URls from email messages

    This class provides methods to parse both HTML and plain text content
    of a MailMessage to collect all contained HTTP(S) links.

    Attributes:
        URL_ATTRS (set[str]): A set of HTML attributes to be scanned
        for URLs (e.g., 'href', 'src')
    """
    def extract_urls(self, mail: MailMessage) -> set[str]:
        """Extracts all URLs from a MailMessage.

        Args:
            mail: The email message.

        Returns:
            set[str]: Set of all extracted URLs.
        """
        html: Optional[str] = mail.html
        text: Optional[str] = mail.text

        urls: set[str] = set()

        if html:
            urls |= set([url for url in self._extract_urls_from_html(html)])

        if text:
            urls |= set([url for url in self._extract_urls_from_text(text)])

        return urls


    def _extract_urls_from_html(self, html: str) -> list[str]:
        """Extracts URLs from HTML with BeautifulSoup.

        Args:
            html: HTML content of an email message.

        Returns:
            list[str]: List of URLs.
        """
        soup = BeautifulSoup(html, "html.parser")
        urls = []
        for tag in soup.find_all(True):
            for attr in URL_ATTRS:
                value = tag.get(attr)
                if isinstance(value, str) and value.startswith("http"):
                    urls.append(value)
        return urls

    def _extract_urls_from_text(self, text: str) -> list[str]:
        """Extracts URls from text with regex.

        Args:
            text: Plain text content of an email message.

        Returns:
            list[str]: List of URls.
        """
        url_pattern = r"https?://[^\s<>\"']+"
        urls_from_pattern = re.findall(url_pattern, text)
        urls = [url.rstrip(")]}.,;:!?") for url in urls_from_pattern]
        return urls
