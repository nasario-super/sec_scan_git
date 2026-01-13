"""
Optimized pattern matching engine for secret detection.

Pre-compiles all patterns and provides efficient batch matching.
"""

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterator, Optional

import yaml

from ..core.models import Severity
from ..utils.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


@dataclass
class CompiledPattern:
    """A pre-compiled secret detection pattern."""
    
    name: str
    regex: re.Pattern
    severity: Severity
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    
    # Context requirements
    context_required: bool = False
    context_patterns: list[re.Pattern] = field(default_factory=list)
    
    # File restrictions
    file_patterns: list[str] = field(default_factory=list)
    
    # Exclusions
    exclude_patterns: list[re.Pattern] = field(default_factory=list)
    
    # Entropy settings
    entropy_check: bool = True
    min_entropy: float = 3.5
    
    # Confidence
    confidence: float = 0.9
    
    # Is this pattern for multiline content?
    multiline: bool = False


@dataclass
class PatternMatch:
    """Result of a pattern match."""
    
    pattern_name: str
    matched_text: str
    start: int
    end: int
    line_number: int
    line_content: str
    severity: Severity
    confidence: float
    is_hardcoded: bool
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)


class PatternEngine:
    """
    High-performance pattern matching engine.
    
    Pre-compiles all patterns at initialization for optimal performance
    during scanning. Supports both single-line and multiline patterns.
    """
    
    # Safe reference patterns - if matched, the secret is likely not hardcoded
    SAFE_REFERENCE_PATTERNS = [
        r"os\.environ",
        r"os\.getenv",
        r"environ\.get",
        r"process\.env",
        r"getenv\(",
        r"config\.get",
        r"settings\.",
        r"vault\.",
        r"secretmanager",
        r"keyvault",
        r"\$\{",
        r"\{\{",
        r"<%=",
        r"<\?=",
        r"System\.getenv",
        r"Environment\.",
    ]
    
    # False positive indicators
    FALSE_POSITIVE_INDICATORS = [
        r"example",
        r"sample",
        r"test",
        r"dummy",
        r"fake",
        r"mock",
        r"placeholder",
        r"xxx+",
        r"your[_-]?(key|token|secret|password)",
        r"<[^>]+>",  # XML/HTML placeholder tags
        r"\*{3,}",  # Asterisks as placeholder
        r"CHANGE[_-]?ME",
        r"TODO",
        r"FIXME",
        r"INSERT[_-]?HERE",
    ]
    
    def __init__(
        self,
        custom_patterns_file: Optional[Path] = None,
        entropy_threshold: float = 4.5,
    ):
        """
        Initialize pattern engine.
        
        Args:
            custom_patterns_file: Path to custom patterns YAML file
            entropy_threshold: Default entropy threshold
        """
        self.entropy_threshold = entropy_threshold
        self.patterns: list[CompiledPattern] = []
        
        # Compile safe reference patterns
        self._safe_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SAFE_REFERENCE_PATTERNS
        ]
        
        # Compile false positive indicators
        self._fp_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.FALSE_POSITIVE_INDICATORS
        ]
        
        # Load default patterns
        self._load_default_patterns()
        
        # Load custom patterns if provided
        if custom_patterns_file:
            self._load_custom_patterns(custom_patterns_file)
        
        logger.info(f"Pattern engine initialized with {len(self.patterns)} patterns")
    
    def _load_default_patterns(self) -> None:
        """Load and compile default patterns."""
        from .secrets import DEFAULT_PATTERNS
        
        for pattern in DEFAULT_PATTERNS:
            self._compile_and_add_pattern(pattern)
    
    def _load_custom_patterns(self, patterns_file: Path) -> None:
        """Load patterns from YAML file."""
        if not patterns_file.exists():
            logger.warning(f"Custom patterns file not found: {patterns_file}")
            return
        
        try:
            with open(patterns_file) as f:
                data = yaml.safe_load(f)
            
            if not data or "patterns" not in data:
                return
            
            for p in data["patterns"]:
                try:
                    flags = re.MULTILINE if p.get("multiline") else 0
                    compiled_regex = re.compile(p["regex"], flags | re.IGNORECASE)
                    
                    # Compile context patterns
                    context_patterns = []
                    for ctx in p.get("context_patterns", []):
                        try:
                            context_patterns.append(re.compile(ctx, re.IGNORECASE))
                        except re.error:
                            pass
                    
                    # Compile exclude patterns
                    exclude_patterns = []
                    for excl in p.get("exclude_patterns", []):
                        try:
                            exclude_patterns.append(re.compile(excl, re.IGNORECASE))
                        except re.error:
                            pass
                    
                    pattern = CompiledPattern(
                        name=p.get("name", "custom"),
                        regex=compiled_regex,
                        severity=Severity(p.get("severity", "high")),
                        description=p.get("description", ""),
                        remediation=p.get("remediation", ""),
                        references=p.get("references", []),
                        context_required=p.get("context_required", False),
                        context_patterns=context_patterns,
                        file_patterns=p.get("file_patterns", []),
                        exclude_patterns=exclude_patterns,
                        entropy_check=p.get("entropy_check", True),
                        min_entropy=p.get("min_entropy", self.entropy_threshold),
                        confidence=p.get("confidence", 0.9),
                        multiline=p.get("multiline", False),
                    )
                    
                    self.patterns.append(pattern)
                    
                except (KeyError, re.error, ValueError) as e:
                    logger.warning(f"Invalid custom pattern: {e}")
                    
        except (yaml.YAMLError, OSError) as e:
            logger.error(f"Error loading custom patterns: {e}")
    
    def _compile_and_add_pattern(self, pattern) -> None:
        """Compile a pattern from the secrets module format."""
        try:
            flags = re.MULTILINE if pattern.multiline else 0
            compiled_regex = re.compile(pattern.regex, flags | re.IGNORECASE)
            
            # Compile context patterns
            context_patterns = []
            for ctx in pattern.context_patterns:
                try:
                    context_patterns.append(re.compile(ctx, re.IGNORECASE))
                except re.error:
                    pass
            
            # Compile exclude patterns
            exclude_patterns = []
            for excl in pattern.exclude_patterns:
                try:
                    exclude_patterns.append(re.compile(excl, re.IGNORECASE))
                except re.error:
                    pass
            
            compiled = CompiledPattern(
                name=pattern.name,
                regex=compiled_regex,
                severity=pattern.severity,
                description=pattern.description,
                remediation=pattern.remediation,
                references=pattern.references,
                context_required=pattern.context_required,
                context_patterns=context_patterns,
                file_patterns=pattern.file_patterns,
                exclude_patterns=exclude_patterns,
                entropy_check=pattern.entropy_check,
                min_entropy=pattern.min_entropy,
                confidence=pattern.confidence,
                multiline=pattern.multiline,
            )
            
            self.patterns.append(compiled)
            
        except re.error as e:
            logger.warning(f"Invalid pattern {pattern.name}: {e}")
    
    def scan_content(
        self,
        content: str,
        file_path: str = "",
        include_context: bool = True,
    ) -> Iterator[PatternMatch]:
        """
        Scan content for secrets.
        
        Args:
            content: Text content to scan
            file_path: Optional file path for pattern filtering
            include_context: Include surrounding context
            
        Yields:
            PatternMatch for each detected secret
        """
        lines = content.split("\n")
        
        for pattern in self.patterns:
            # Check file pattern restrictions
            if pattern.file_patterns and file_path:
                if not any(
                    Path(file_path).match(fp) for fp in pattern.file_patterns
                ):
                    continue
            
            # Search content
            for match in pattern.regex.finditer(content):
                # Get line number
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_num = content[:match.start()].count("\n") + 1
                line_end = content.find("\n", match.end())
                if line_end == -1:
                    line_end = len(content)
                line_content = content[line_start:line_end]
                
                # Check exclusions
                if self._should_exclude(match.group(), line_content, pattern):
                    continue
                
                # Check context requirement
                if pattern.context_required:
                    if not self._has_required_context(line_content, pattern):
                        continue
                
                # Check entropy if enabled
                if pattern.entropy_check:
                    secret_value = self._extract_secret_value(match.group())
                    entropy = calculate_entropy(secret_value)
                    if entropy < pattern.min_entropy:
                        continue
                
                # Check if hardcoded
                is_hardcoded = self._is_hardcoded(line_content)
                
                # Get context
                context_before = []
                context_after = []
                if include_context:
                    context_before = lines[max(0, line_num - 3):line_num - 1]
                    context_after = lines[line_num:min(len(lines), line_num + 2)]
                
                yield PatternMatch(
                    pattern_name=pattern.name,
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    line_number=line_num,
                    line_content=line_content,
                    severity=pattern.severity,
                    confidence=pattern.confidence if is_hardcoded else pattern.confidence * 0.7,
                    is_hardcoded=is_hardcoded,
                    context_before=context_before,
                    context_after=context_after,
                )
    
    def scan_file(
        self,
        file_path: Path,
        include_context: bool = True,
    ) -> Iterator[PatternMatch]:
        """
        Scan a file for secrets.
        
        Args:
            file_path: Path to file
            include_context: Include surrounding context
            
        Yields:
            PatternMatch for each detected secret
        """
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            yield from self.scan_content(
                content,
                str(file_path),
                include_context,
            )
        except OSError as e:
            logger.warning(f"Could not read file {file_path}: {e}")
    
    def _should_exclude(
        self,
        matched_text: str,
        line_content: str,
        pattern: CompiledPattern,
    ) -> bool:
        """Check if match should be excluded."""
        # Check pattern-specific exclusions
        for exclude in pattern.exclude_patterns:
            if exclude.search(line_content):
                return True
        
        # Check global false positive indicators
        for fp in self._fp_patterns:
            if fp.search(matched_text):
                return True
        
        return False
    
    def _has_required_context(
        self,
        line_content: str,
        pattern: CompiledPattern,
    ) -> bool:
        """Check if required context patterns are present."""
        for ctx_pattern in pattern.context_patterns:
            if ctx_pattern.search(line_content):
                return True
        return False
    
    def _is_hardcoded(self, line_content: str) -> bool:
        """Check if value appears hardcoded vs referenced."""
        for safe_pattern in self._safe_patterns:
            if safe_pattern.search(line_content):
                return False
        return True
    
    def _extract_secret_value(self, matched_text: str) -> str:
        """Extract the actual secret value from a match."""
        # Remove common prefixes/suffixes
        value = matched_text
        if "=" in value:
            value = value.split("=", 1)[-1]
        if ":" in value:
            value = value.split(":", 1)[-1]
        
        return value.strip("\"' \t")
    
    def get_pattern_count(self) -> int:
        """Get number of loaded patterns."""
        return len(self.patterns)
    
    def get_patterns_by_severity(self, severity: Severity) -> list[CompiledPattern]:
        """Get patterns filtered by severity."""
        return [p for p in self.patterns if p.severity == severity]


@lru_cache(maxsize=10000)
def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string (cached).
    
    Higher entropy suggests more randomness (potential secret).
    
    Args:
        text: Text to analyze
        
    Returns:
        Entropy value (0-8 for ASCII)
    """
    import math
    from collections import Counter
    
    if not text:
        return 0.0
    
    # Count character frequencies
    freq = Counter(text)
    length = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    
    return entropy


# Global pattern engine instance (lazy loaded)
_pattern_engine: Optional[PatternEngine] = None


def get_pattern_engine(
    custom_patterns_file: Optional[Path] = None,
    entropy_threshold: float = 4.5,
) -> PatternEngine:
    """
    Get or create the global pattern engine.
    
    Args:
        custom_patterns_file: Path to custom patterns
        entropy_threshold: Entropy threshold
        
    Returns:
        PatternEngine instance
    """
    global _pattern_engine
    
    if _pattern_engine is None:
        _pattern_engine = PatternEngine(
            custom_patterns_file=custom_patterns_file,
            entropy_threshold=entropy_threshold,
        )
    
    return _pattern_engine


def reset_pattern_engine() -> None:
    """Reset the global pattern engine (useful for testing)."""
    global _pattern_engine
    _pattern_engine = None
