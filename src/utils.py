"""Utility functions for document processing and text extraction."""

import os
import re
from pathlib import Path
import PyPDF2
from docx import Document

# Try to import python-magic, but make it optional
try:
    import magic
    MAGIC_AVAILABLE = True
except (ImportError, OSError):
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available. Magic byte validation will use fallback method.")

# Security limits
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Zero-width / invisible Unicode characters to strip from extracted text
_ZERO_WIDTH_CHARS = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\u2061\u2062\u2063'
    r'\u2064\ufeff\u00ad]'
)

# Expected MIME types for each extension
_ALLOWED_MIME_TYPES = {
    '.txt': ['text/plain', 'text/x-log', 'application/octet-stream'],
    '.pdf': ['application/pdf'],
    '.docx': [
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/zip',  # DOCX is a ZIP archive
        'application/octet-stream'
    ],
}


def sanitize_text(text: str) -> str:
    """Remove zero-width and invisible Unicode characters from text.
    Also normalize Unicode to prevent encoding bypass attacks.
    """
    import unicodedata
    # Remove zero-width characters
    text = _ZERO_WIDTH_CHARS.sub('', text)
    # Normalize Unicode (prevents İGNORE vs IGNORE attacks)
    text = unicodedata.normalize('NFKC', text)
    return text


def validate_file_magic_bytes(file_path: str, expected_ext: str) -> bool:
    """Validate file magic bytes match the extension to prevent magic byte attacks.
    
    Args:
        file_path: Path to file
        expected_ext: Expected extension (e.g., '.pdf')
    
    Returns:
        True if magic bytes match extension, False otherwise
    """
    # Try using python-magic if available
    if MAGIC_AVAILABLE:
        try:
            mime = magic.from_file(file_path, mime=True)
            allowed_mimes = _ALLOWED_MIME_TYPES.get(expected_ext, [])
            if mime in allowed_mimes:
                return True
            # If MIME doesn't match, fall through to manual check
        except Exception as e:
            print(f"Warning: python-magic failed ({e}), using fallback validation")
    
    # Fallback: manual magic byte checking
    try:
        with open(file_path, 'rb') as f:
            header = f.read(8)
        
        if expected_ext == '.pdf':
            return header.startswith(b'%PDF')
        elif expected_ext == '.docx':
            # DOCX is a ZIP file
            return header.startswith(b'PK\x03\x04')
        elif expected_ext == '.txt':
            # Text files don't have magic bytes, allow anything
            return True
        
        return False
    except Exception as e:
        print(f"Warning: Magic byte validation failed ({e}), allowing file")
        return True  # Allow file if validation fails (fail-open for usability)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and encoding attacks.
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    """
    # Remove null bytes
    filename = filename.replace('\x00', '')
    
    # Remove path separators
    filename = filename.replace('/', '_').replace('\\', '_')
    
    # Remove parent directory references
    filename = filename.replace('..', '')
    
    # URL decode to prevent encoding bypass
    from urllib.parse import unquote
    filename = unquote(filename)
    
    # Only allow alphanumeric, dash, underscore, dot
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # Prevent double extensions (e.g., file.txt.exe)
    parts = filename.split('.')
    if len(parts) > 2:
        # Keep only the last extension
        filename = '.'.join(parts[:-1]).replace('.', '_') + '.' + parts[-1]
    
    return filename


def validate_file_size(file_path):
    """Validate file size before processing."""
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {file_size / (1024*1024):.1f}MB (max: 50MB)")
    if file_size == 0:
        raise ValueError("File is empty")
    return file_size


def read_text_file(file_path):
    """Read plain text file."""
    validate_file_size(file_path)
    with open(file_path, 'r', encoding='utf-8') as f:
        return sanitize_text(f.read())


def read_pdf_file(file_path):
    """Extract text from PDF file."""
    validate_file_size(file_path)
    text = []
    try:
        with open(file_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            for page in pdf_reader.pages:
                text.append(page.extract_text())
        return sanitize_text('\n'.join(text))
    except Exception as e:
        raise ValueError(f"Error reading PDF: {e}")


def read_docx_file(file_path):
    """Extract text from DOCX file."""
    validate_file_size(file_path)
    try:
        doc = Document(file_path)
        return sanitize_text('\n'.join([paragraph.text for paragraph in doc.paragraphs]))
    except Exception as e:
        raise ValueError(f"Error reading DOCX: {e}")


def read_policy_document(file_path):
    """Read policy document based on file extension."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")

    ext = Path(file_path).suffix.lower()
    
    # Validate extension
    if ext not in ['.txt', '.pdf', '.docx']:
        raise ValueError(f"Unsupported file format: {ext}. Supported: .txt, .pdf, .docx")
    
    # Validate magic bytes to prevent magic byte injection attacks
    if not validate_file_magic_bytes(file_path, ext):
        raise ValueError(
            f"File magic bytes do not match extension {ext}. "
            f"Possible file type mismatch or magic byte injection attack."
        )

    if ext == '.txt':
        return read_text_file(file_path)
    elif ext == '.pdf':
        return read_pdf_file(file_path)
    elif ext == '.docx':
        return read_docx_file(file_path)


def save_output(content, output_path):
    """Save output to file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
