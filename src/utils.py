"""Utility functions for document processing and text extraction."""

import os
import re
from pathlib import Path
import PyPDF2
from docx import Document

# Security limits
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Zero-width / invisible Unicode characters to strip from extracted text
_ZERO_WIDTH_CHARS = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\u2061\u2062\u2063'
    r'\u2064\ufeff\u00ad]'
)


def sanitize_text(text: str) -> str:
    """Remove zero-width and invisible Unicode characters from text."""
    return _ZERO_WIDTH_CHARS.sub('', text)


def validate_file_size(file_path):
    """Validate file size before processing."""
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {file_size / (1024*1024):.1f}MB (max: 50MB)")
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

    if ext == '.txt':
        return read_text_file(file_path)
    elif ext == '.pdf':
        return read_pdf_file(file_path)
    elif ext == '.docx':
        return read_docx_file(file_path)
    else:
        raise ValueError(f"Unsupported file format: {ext}. Supported: .txt, .pdf, .docx")


def save_output(content, output_path):
    """Save output to file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
