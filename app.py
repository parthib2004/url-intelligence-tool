from flask import Flask, render_template, request, send_file
import requests, socket, ssl
import whois
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import nltk
from nltk.tokenize.punkt import PunktSentenceTokenizer
from nltk.tokenize.regexp import RegexpTokenizer
from nltk.corpus import stopwords
from nltk.probability import FreqDist
from string import punctuation
import heapq
import re
import qrcode
import io
import base64
import json
import hashlib
from datetime import datetime, timezone
import ipaddress
from typing import Dict, Any
import socket
import dns.resolver
import pdfkit
import os
from dotenv import load_dotenv
load_dotenv()

# Initialize tokenizers
word_tokenizer = RegexpTokenizer(r'\w+')

def calculate_domain_age(whois_data: Dict[str, Any]) -> tuple[int, str]:
    try:
        if not whois_data or not whois_data.get('creation_date'):
            return 0, "Unknown"
        
        creation_date = whois_data['creation_date']
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if not isinstance(creation_date, datetime):
            return 0, "Unknown"
        
        # Ensure both datetimes are timezone-aware (UTC)
        now = datetime.now(timezone.utc)
        if creation_date.tzinfo is None or creation_date.tzinfo.utcoffset(creation_date) is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        
        age_days = (now - creation_date).days
        
        if age_days > 365 * 5:  # 5+ years
            return 100, f"{age_days // 365} years"
        elif age_days > 365 * 2:  # 2-5 years
            return 80, f"{age_days // 365} years"
        elif age_days > 365:  # 1-2 years
            return 60, f"{age_days // 365} year"
        elif age_days > 180:  # 6 months - 1 year
            return 40, f"{age_days // 30} months"
        elif age_days > 30:  # 1-6 months
            return 20, f"{age_days // 30} months"
        else:  # < 1 month
            return 0, f"{age_days} days"
    except Exception as e:
        print(f"Error calculating domain age: {e}")
        return 0, "Unknown"

def is_ip_suspicious(ip: str) -> tuple[bool, int]:
    try:
        # Check if it's a private IP
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return True, 0
        
        # Try reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            
            # Check if it's a cloud/VPS provider
            vps_indicators = ['aws', 'azure', 'google', 'digitalocean', 'linode',
                            'vultr', 'hetzner', 'ovh', 'cloud']
            
            is_vps = any(indicator in hostname.lower() for indicator in vps_indicators)
            score = 60 if is_vps else 80
            
            return is_vps, score
        except:
            # If reverse DNS fails, it's somewhat suspicious
            return True, 40
            
    except Exception as e:
        print(f"Error checking IP: {e}")
        return True, 0

def calculate_trust_score(domain_data: Dict[str, Any]) -> Dict[str, Any]:
    scores = []
    
    # 1. Domain Age Score (max 100)
    age_score, age_text = calculate_domain_age(domain_data.get('whois', {}))
    scores.append(age_score)
    
    # 2. SSL Score (max 100)
    ssl_score = 100 if domain_data.get('ssl_info') else 0
    scores.append(ssl_score)
    
    # 3. WHOIS Privacy Score (max 100)
    whois_data = domain_data.get('whois', {})
    is_private = getattr(whois_data, 'private', False)
    whois_score = 60 if is_private else 100  # Slight penalty for private WHOIS
    scores.append(whois_score)
    
    # 4. IP/Hosting Score (max 100)
    ip_info = domain_data.get('ip_info', {})
    is_vps, ip_score = is_ip_suspicious(ip_info.get('ip', '0.0.0.0'))
    scores.append(ip_score)
    
    # Calculate final score (weighted average)
    weights = [0.4, 0.3, 0.1, 0.2]  # Age: 40%, SSL: 30%, WHOIS: 10%, IP: 20%
    final_score = sum(score * weight for score, weight in zip(scores, weights))
    
    return {
        'trust_score': round(final_score),
        'domain_age': age_text,
        'is_vps': is_vps
    }

def download_nltk_data():
    try:
        # Download only stopwords as we'll use regex tokenizer instead of punkt
        nltk.download('stopwords', quiet=True)
    except Exception as e:
        print(f"Failed to download NLTK data: {str(e)}")
        # Continue with fallback methods even if download fails

# Ensure NLTK data is downloaded
download_nltk_data()

app = Flask(__name__)

def analyze_text(text):
    try:
        if not text or len(str(text).strip()) == 0:
            return default_analysis_result()
            
        # Ensure text is string and clean it
        text = ' '.join(str(text).split())  # Normalize whitespace
        
        # Use regex for sentence splitting - look for .!? followed by space and uppercase letter
        sentences = [s.strip() for s in re.split(r'[.!?]+\s+(?=[A-Z])', text) if s.strip()]
        if not sentences and text.strip():  # If no sentences found but text exists
            sentences = [text.strip()]  # Use the entire text as one sentence
            
        # Use regex word tokenizer for consistent results
        words = word_tokenizer.tokenize(text.lower())
        
        # Remove stopwords
        try:
            stop_words = set(stopwords.words('english'))
        except:
            # Fallback to basic stopwords
            stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        
        words = [word for word in words if word not in stop_words and word not in punctuation]
        
        if not words or not sentences:
            return default_analysis_result()
        
        # Calculate word frequency
        freq_dist = FreqDist(words)
        
        # Calculate sentence scores based on word frequency
        sentence_scores = {}
        for sentence in sentences:
            # Use the same word tokenizer for consistency
            sentence_words = word_tokenizer.tokenize(sentence.lower())
            for word in sentence_words:
                if word in freq_dist:
                    if sentence not in sentence_scores:
                        sentence_scores[sentence] = freq_dist[word]
                    else:
                        sentence_scores[sentence] += freq_dist[word]
        
        # Get top 3 sentences for summary
        try:
            summary_sentences = heapq.nlargest(min(3, len(sentence_scores)), sentence_scores, key=sentence_scores.get)
            summary = ' '.join(summary_sentences)
        except:
            # Fallback to first sentence if summary generation fails
            summary = sentences[0] if sentences else "No summary available"
        
        # Get top keywords
        try:
            keywords = heapq.nlargest(min(5, len(freq_dist)), freq_dist, key=freq_dist.get)
        except:
            keywords = list(freq_dist.keys())[:5] if freq_dist else ["No keywords found"]
        
        # Determine content type
        word_count = len(words)
        if word_count > 1000:
            content_type = "Long Article"
        elif word_count > 300:
            content_type = "Article"
        elif word_count > 100:
            content_type = "Short Article"
        else:
            content_type = "Brief Content"
        
        # Calculate readability score using an improved formula
        try:
            # For very short content, use a different scoring method
            if word_count < 20:
                # Check if it's a title or heading
                avg_word_length = sum(len(word) for word in words) / len(words) if words else 0
                words_per_sentence = len(words) / len(sentences) if sentences else 0
                
                # Score based on reasonable title/heading metrics
                if avg_word_length <= 8 and words_per_sentence <= 10:
                    readability_score = 80  # Good for a title
                else:
                    readability_score = 60  # Average for short content
            else:
                # For longer content, use more sophisticated analysis
                avg_sentence_length = len(words) / len(sentences)
                avg_word_length = sum(len(word) for word in words) / len(words)
                
                # Ideal ranges:
                # - Sentence length: 10-20 words
                # - Word length: 4-6 characters
                sentence_score = 100 - abs(15 - avg_sentence_length) * 3
                word_length_score = 100 - abs(5 - avg_word_length) * 10
                
                # Combine scores with adjustments for text length
                base_score = (sentence_score + word_length_score) / 2
                
                if word_count < 50:
                    base_score *= 0.9  # Small penalty for short texts
                elif word_count > 2000:
                    base_score *= 0.95  # Tiny penalty for very long texts
                
                readability_score = max(0, min(100, base_score))
        except:
            # Provide a reasonable default based on content length
            if word_count < 10:
                readability_score = 70  # Assume it's a reasonable title/heading
            elif word_count < 50:
                readability_score = 60  # Assume it's decent short content
            else:
                readability_score = 50  # Middle ground for longer content
        
        return {
            'summary': summary,
            'keywords': keywords,
            'readability_score': readability_score,
            'word_count': word_count,
            'sentence_count': len(sentences),
            'content_type': content_type
        }
    except Exception as e:
        print(f"Error in analyze_text: {str(e)}")
        return default_analysis_result()

def default_analysis_result():
    """Return default values for analysis when processing fails"""
    return {
        'summary': 'No content available',
        'keywords': ['No keywords found'],
        'readability_score': 0,
        'word_count': 0,
        'sentence_count': 0,
        'content_type': 'No content'
    }

def detect_tech_stack(url, response, soup):
    """Detect technologies used by the website"""
    tech_stack = {
        'Frontend': set(),
        'Backend': set(),
        'Framework': set(),
        'Analytics': set(),
        'Server': set(),
        'CMS': set(),
        'Security': set()
    }
    
    # Check headers
    headers = response.headers
    server = headers.get('Server', '')
    if server:
        tech_stack['Server'].add(server)
    
    # Check security headers
    security_headers = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-XSS-Protection'
    ]
    for header in security_headers:
        if header in headers:
            tech_stack['Security'].add(header)
    
    # Check for common frontend libraries
    scripts = soup.find_all('script')
    for script in scripts:
        src = script.get('src', '')
        if 'react' in src.lower():
            tech_stack['Frontend'].add('React')
        elif 'vue' in src.lower():
            tech_stack['Frontend'].add('Vue.js')
        elif 'angular' in src.lower():
            tech_stack['Frontend'].add('Angular')
        elif 'jquery' in src.lower():
            tech_stack['Frontend'].add('jQuery')
    
    # Check meta tags and generator
    meta_generator = soup.find('meta', attrs={'name': 'generator'})
    if meta_generator:
        content = meta_generator.get('content', '').lower()
        if 'wordpress' in content:
            tech_stack['CMS'].add('WordPress')
        elif 'drupal' in content:
            tech_stack['CMS'].add('Drupal')
        elif 'joomla' in content:
            tech_stack['CMS'].add('Joomla')
    
    # Check for analytics
    for script in scripts:
        src = script.get('src', '')
        text = script.string or ''
        if 'google-analytics' in src or 'gtag' in text or 'GA_TRACKING_ID' in text:
            tech_stack['Analytics'].add('Google Analytics')
        elif 'hotjar' in src:
            tech_stack['Analytics'].add('Hotjar')
    
    # Check for common frameworks
    body_classes = soup.find('body', class_=True)
    if body_classes:
        classes = ' '.join(body_classes['class']).lower()
        if 'elementor' in classes:
            tech_stack['Framework'].add('Elementor')
        elif 'divi' in classes:
            tech_stack['Framework'].add('Divi')
    
    # Check for backend technologies
    cookies = response.cookies
    for cookie in cookies:
        if 'PHPSESSID' in cookie.name:
            tech_stack['Backend'].add('PHP')
        elif 'JSESSIONID' in cookie.name:
            tech_stack['Backend'].add('Java')
        elif 'ASPXAUTH' in cookie.name:
            tech_stack['Backend'].add('ASP.NET')
    
    # Clean up empty categories
    tech_stack = {k: list(v) for k, v in tech_stack.items() if v}
    
    return tech_stack

def generate_qr_code(url):
    """Generate a QR code for the given URL and return as base64 string"""
    try:
        # Create QR code instance
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(url)
        qr.make(fit=True)

        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 string
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    except Exception as e:
        print(f"Error generating QR code: {str(e)}")
        return None

def get_metadata(url, soup=None):
    try:
        if soup is None:
            # Get the webpage content
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract title and meta description
        title = soup.title.string.strip() if soup.title and soup.title.string else url
        
        # --- Open Graph Extraction ---
        og_title = None
        og_description = None
        og_image = None
        for meta in soup.find_all('meta'):
            prop = meta.get('property', '').lower()
            if prop == 'og:title':
                og_title = meta.get('content')
            elif prop == 'og:description':
                og_description = meta.get('content')
            elif prop == 'og:image':
                og_image = meta.get('content')
        # Fallbacks if not found
        if not og_title:
            og_title = title
        if not og_description:
            og_description = None  # Will fallback to description below
        if not og_image:
            og_image = None
        # --- End Open Graph Extraction ---
        
        # Try to get meta description from multiple possible meta tags
        description = None
        for meta in soup.find_all('meta'):
            if meta.get('name', '').lower() == 'description' or meta.get('property', '').lower() in ['og:description', 'twitter:description']:
                description = meta.get('content')
                if description:
                    break
        if not description:
            # Try to find a subtitle or h1 tag
            h1 = soup.find('h1')
            if h1:
                description = h1.get_text().strip()
            else:
                description = "N/A"
        
        # Get all text content from the page
        text_elements = []
        
        # Look for main content containers first
        main_content = soup.find(['main', 'article']) or soup
        
        # Get text from content elements in order of importance
        for tag in ['p', 'h1', 'h2', 'h3', 'h4', 'li']:
            elements = main_content.find_all(tag)
            for elem in elements:
                # Skip if it's a navigation or menu item
                if any(cls in elem.get('class', []) for cls in ['nav', 'menu', 'footer']):
                    continue
                text = elem.get_text().strip()
                if text and len(text.split()) > 2:  # Require at least 3 words
                    text_elements.append(text)
        
        # If no content found, try sections and divs with substantial content
        if not text_elements:
            for elem in main_content.find_all(['section', 'div']):
                if elem.get('class') and any(cls in elem.get('class', []) for cls in ['content', 'main', 'article']):
                    text = elem.get_text().strip()
                    if text and len(text.split()) > 10:
                        text_elements.append(text)
        
        # Join all text content
        content = ' '.join(text_elements)
        
        # If still no content, create a meaningful fallback
        if not content:
            content_parts = []
            if title and title != "N/A":
                content_parts.append(title)
            if description and description != "N/A":
                content_parts.append(description)
            if not content_parts:
                # Extract any visible text as last resort
                visible_text = [text for text in soup.stripped_strings if len(text.strip()) > 20]
                content = ' '.join(visible_text[:3]) if visible_text else "No readable content found"
            else:
                content = ' '.join(content_parts)
        
        # Perform AI analysis on the content
        ai_analysis = analyze_text(content)
        
        # Return metadata with default values if something is missing
        return {
            "title": title if title else "No title found",
            "description": description if description != "N/A" else "No description available",
            "keywords": ai_analysis.get('keywords', ['No keywords found']),
            "ai_summary": ai_analysis.get('summary', 'No summary available'),
            "readability": min(100, max(0, ai_analysis.get('readability_score', 0))),
            "word_count": ai_analysis.get('word_count', 0),
            "sentence_count": ai_analysis.get('sentence_count', 0),
            "content_type": ai_analysis.get('content_type', 'Unknown'),
            # Add Open Graph fields
            "og_title": og_title if og_title else (title if title else None),
            "og_description": og_description if og_description else (description if description != "N/A" else None),
            "og_image": og_image
        }
    except Exception as e:
        print(f"Error in get_metadata: {str(e)}")
        # Return default values if there's an error
        return {
            "title": "Error fetching content",
            "description": "Could not analyze the webpage",
            "keywords": ["Error"],
            "ai_summary": "There was an error analyzing this webpage",
            "readability": 0,
            "word_count": 0,
            "sentence_count": 0,
            "content_type": "Error",
            "og_title": None,
            "og_description": None,
            "og_image": None
        }

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "issuer": cert.get('issuer', 'N/A'),
                "valid_from": cert.get('notBefore'),
                "valid_to": cert.get('notAfter')
            }
    except:
        return {}

def get_ip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        resp = requests.get(f"https://ipinfo.io/{ip}/json").json()
        return {
            "ip": ip,
            "city": resp.get("city", "N/A"),
            "region": resp.get("region", "N/A"),
            "country": resp.get("country", "N/A"),
            "org": resp.get("org", "N/A")
        }
    except:
        return {}

def trace_redirects(url, max_redirects=10):
    """Trace all redirects for a given URL"""
    redirects = []
    try:
        # Custom headers to mimic browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        current_url = url
        visited = set()  # To detect redirect loops
        
        for _ in range(max_redirects):
            if current_url in visited:
                redirects.append({
                    'url': current_url,
                    'status_code': 'Loop Detected',
                    'type': 'Redirect Loop',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                break
                
            visited.add(current_url)
            
            try:
                response = requests.get(
                    current_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=5
                )
                
                redirect_type = 'Direct'
                if response.status_code in [301, 302, 303, 307, 308]:
                    redirect_type = {
                        301: 'Permanent Redirect',
                        302: 'Temporary Redirect',
                        303: 'See Other',
                        307: 'Temporary Redirect (Strict)',
                        308: 'Permanent Redirect (Strict)'
                    }.get(response.status_code, 'Unknown Redirect')
                
                redirects.append({
                    'url': current_url,
                    'status_code': response.status_code,
                    'type': redirect_type,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    if 'location' in response.headers:
                        next_url = response.headers['location']
                        # Handle relative redirects
                        if not next_url.startswith(('http://', 'https://')):
                            next_url = urljoin(current_url, next_url)
                        current_url = next_url
                        continue
                
                # If we reach here, no more redirects
                break
                
            except requests.exceptions.RequestException as e:
                redirects.append({
                    'url': current_url,
                    'status_code': 'Error',
                    'type': str(e),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                break
        
        return redirects
    except Exception as e:
        return [{
            'url': url,
            'status_code': 'Error',
            'type': f'Failed to trace redirects: {str(e)}',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }]

def html_to_pdf_online(html):
    import requests
    api_key = os.environ.get('PDFSHIFT_API_KEY')
    if not api_key:
        raise Exception('PDFSHIFT_API_KEY environment variable not set!')
    response = requests.post(
        'https://api.pdfshift.io/v3/convert/pdf',
        headers={ 'X-API-Key': api_key },
        json={
            'source': html,
            'landscape': False,
            'use_print': False
        }
    )
    if response.ok:
        return response.content  # This is the PDF bytes
    else:
        raise Exception('PDF conversion failed: ' + response.text)

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    if request.method == "POST":
        url = request.form.get("url")
        if not url.startswith("http"):
            url = "http://" + url
        domain = urlparse(url).netloc

        # Get webpage content first as it's needed for multiple analyses
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception as e:
            print(f"Error fetching URL: {str(e)}")
            response = None
            soup = None

        result["url"] = url
        result["domain"] = domain

        try:
            result["metadata"] = get_metadata(url, soup) if soup else {
                'title': 'Could not fetch page',
                'description': 'The page could not be accessed',
                'keywords': [],
                'og_title': None,
                'og_description': None,
                'og_image': None
            }
        except Exception as e:
            print(f"Error getting metadata: {str(e)}")
            result["metadata"] = {
                'title': 'Error analyzing page',
                'description': 'There was an error analyzing this page',
                'keywords': [],
                'og_title': None,
                'og_description': None,
                'og_image': None
            }

        try:
            whois_result = whois.whois(domain)
            result["whois"] = {
                'registrar': whois_result.get('registrar', 'Unknown'),
                'creation_date': whois_result.get('creation_date'),
                'expiration_date': whois_result.get('expiration_date'),
                'private': whois_result.get('name_servers') is None
            }
        except Exception as e:
            print(f"Error getting WHOIS: {str(e)}")
            result["whois"] = {'registrar': 'Unknown', 'creation_date': None, 'expiration_date': None, 'private': False}

        try:
            result["ip_info"] = get_ip_info(domain)
        except Exception as e:
            print(f"Error getting IP info: {str(e)}")
            result["ip_info"] = None

        try:
            result["ssl_info"] = get_ssl_info(domain)
        except Exception as e:
            print(f"Error getting SSL info: {str(e)}")
            result["ssl_info"] = None

        try:
            result["qr_code"] = generate_qr_code(url)
        except Exception as e:
            print(f"Error generating QR code: {str(e)}")
            result["qr_code"] = None

        try:
            # Calculate domain trust score
            trust_data = calculate_trust_score(result)
            result.update(trust_data)
        except Exception as e:
            print(f"Error calculating trust score: {str(e)}")
            result["trust_score"] = 0
        
        # Add tech stack detection
        if response and soup:
            result["tech_stack"] = detect_tech_stack(url, response, soup)
            
        # Add redirect chain tracing
        result["redirects"] = trace_redirects(url)

    return render_template("index.html", result=result)

@app.route("/download_pdf", methods=["POST"])
def download_pdf():
    url = request.form.get("url")
    if not url:
        return "No URL provided", 400
    if not url.startswith("http"):
        url = "http://" + url
    domain = urlparse(url).netloc

    # Repeat the same analysis as in index()
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        print(f"Error fetching URL: {str(e)}")
        response = None
        soup = None

    result = {}
    result["url"] = url
    result["domain"] = domain
    result["metadata"] = get_metadata(url)
    whois_result = whois.whois(domain)
    result["whois"] = {
        'registrar': whois_result.get('registrar', 'Unknown'),
        'creation_date': whois_result.get('creation_date'),
        'expiration_date': whois_result.get('expiration_date'),
        'private': whois_result.get('name_servers') is None
    }
    result["ip_info"] = get_ip_info(domain)
    result["ssl_info"] = get_ssl_info(domain)
    result["qr_code"] = generate_qr_code(url)
    trust_data = calculate_trust_score(result)
    result.update(trust_data)
    if response and soup:
        result["tech_stack"] = detect_tech_stack(url, response, soup)
    result["redirects"] = trace_redirects(url)

    # Render the report as HTML (use a special template or the same one)
    rendered = render_template("report.html", result=result)
    # Generate PDF from HTML using PDFShift
    pdf = html_to_pdf_online(rendered)
    return send_file(
        io.BytesIO(pdf),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"url_report_{domain}.pdf"
    )

if __name__ == "__main__":
    app.run(debug=True)