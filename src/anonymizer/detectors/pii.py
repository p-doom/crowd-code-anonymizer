"""PII detection layer using Microsoft Presidio."""

from dataclasses import dataclass

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider


@dataclass
class PIIFinding:
    """Represents detected PII."""
    
    entity_type: str
    text: str
    start: int
    end: int
    score: float
    
    @property
    def redaction_label(self) -> str:
        """Get the redaction label for this finding."""
        # Map Presidio entity types to simpler labels
        type_map = {
            "EMAIL_ADDRESS": "EMAIL",
            "PHONE_NUMBER": "PHONE",
            "CREDIT_CARD": "CREDIT_CARD",
            "IP_ADDRESS": "IP_ADDRESS",
            "PERSON": "PERSON_NAME",
            "LOCATION": "LOCATION",
            "DATE_TIME": "DATE_TIME",
            "NRP": "NRP",  # Nationality, Religion, Political group
            "MEDICAL_LICENSE": "MEDICAL_ID",
            "URL": "URL",
            "US_SSN": "SSN",
            "US_PASSPORT": "PASSPORT",
            "US_DRIVER_LICENSE": "DRIVER_LICENSE",
            "UK_NHS": "NHS_NUMBER",
            "IBAN_CODE": "IBAN",
            "US_BANK_NUMBER": "BANK_NUMBER",
            "US_ITIN": "TAX_ID",
            "AU_ABN": "BUSINESS_ID",
            "AU_ACN": "COMPANY_ID",
            "AU_TFN": "TAX_ID",
            "AU_MEDICARE": "MEDICARE",
            "SG_NRIC_FIN": "NATIONAL_ID",
            "IN_PAN": "TAX_ID",
            "IN_AADHAAR": "NATIONAL_ID",
        }
        return type_map.get(self.entity_type, self.entity_type)


class PIIDetector:
    """Detect PII using Microsoft Presidio analyzer."""
    
    # Entity types to detect
    DEFAULT_ENTITIES = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER", 
        "CREDIT_CARD",
        "IP_ADDRESS",
        "PERSON",
        "LOCATION",
        "URL",
        "US_SSN",
        "US_PASSPORT",
        "US_DRIVER_LICENSE",
        "IBAN_CODE",
        "US_BANK_NUMBER",
    ]
    
    STRICT_ENTITIES = DEFAULT_ENTITIES + [
        "DATE_TIME",
        "NRP",
        "MEDICAL_LICENSE",
        "UK_NHS",
        "US_ITIN",
        "AU_ABN",
        "AU_ACN", 
        "AU_TFN",
        "AU_MEDICARE",
        "SG_NRIC_FIN",
        "IN_PAN",
        "IN_AADHAAR",
    ]
    
    def __init__(self, strict: bool = False, score_threshold: float = 0.5):
        """Initialize the PII detector.
        
        Args:
            strict: If True, detect more entity types with lower thresholds
            score_threshold: Minimum confidence score to consider a finding
        """
        self.strict = strict
        self.score_threshold = score_threshold if not strict else 0.3
        self.entities = self.STRICT_ENTITIES if strict else self.DEFAULT_ENTITIES
        
        # Initialize Presidio analyzer
        # Use a simple spacy model for NER
        self._analyzer: AnalyzerEngine | None = None
    
    @property
    def analyzer(self) -> AnalyzerEngine:
        """Lazy initialization of the analyzer engine."""
        if self._analyzer is None:
            import spacy
            
            # Try models in order of preference: transformer (GPU) > large > small
            models_to_try = [
                "en_core_web_trf",  # Transformer model - best accuracy, GPU-accelerated
                "en_core_web_lg",   # Large model - good accuracy
                "en_core_web_sm",   # Small model - fastest CPU fallback
            ]
            
            nlp = None
            model_used = None
            
            for model_name in models_to_try:
                try:
                    nlp = spacy.load(model_name)
                    model_used = model_name
                    
                    # Check if GPU is available and being used
                    if spacy.prefer_gpu():
                        print(f"PII detector: Using {model_name} with GPU acceleration")
                    else:
                        print(f"PII detector: Using {model_name} on CPU")
                    break
                except OSError:
                    continue
            
            if nlp is not None:
                try:
                    configuration = {
                        "nlp_engine_name": "spacy",
                        "models": [{"lang_code": "en", "model_name": model_used}],
                    }
                    provider = NlpEngineProvider(nlp_configuration=configuration)
                    nlp_engine = provider.create_engine()
                    self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
                except Exception:
                    self._analyzer = AnalyzerEngine()
            else:
                # No spacy model found - fall back to pattern matching only
                print("PII detector: No spaCy model found, using pattern matching only")
                self._analyzer = AnalyzerEngine()
        return self._analyzer
    
    def detect(self, text: str, language: str = "en") -> list[PIIFinding]:
        """Detect PII in the given text.
        
        Args:
            text: Text to scan for PII
            language: Language code for analysis
            
        Returns:
            List of PIIFinding objects
        """
        findings: list[PIIFinding] = []
        
        if not text or not text.strip():
            return findings
        
        try:
            results: list[RecognizerResult] = self.analyzer.analyze(
                text=text,
                entities=self.entities,
                language=language,
            )
            
            for result in results:
                if result.score >= self.score_threshold:
                    # Extract the actual text that was detected
                    detected_text = text[result.start:result.end]
                    
                    findings.append(PIIFinding(
                        entity_type=result.entity_type,
                        text=detected_text,
                        start=result.start,
                        end=result.end,
                        score=result.score,
                    ))
        except Exception:
            # Don't let detection errors stop the pipeline
            pass
        
        return findings
    
    def detect_multiline(self, text: str, language: str = "en") -> list[PIIFinding]:
        """Detect PII in multiline text.
        
        For multiline content, we detect on the full text to preserve
        context for NER-based detection.
        
        Args:
            text: Multiline text to scan
            language: Language code
            
        Returns:
            List of PIIFinding objects
        """
        return self.detect(text, language)
    
    def detect_batch(
        self, 
        texts: list[str], 
        language: str = "en"
    ) -> list[list[PIIFinding]]:
        """Detect PII in a batch of texts efficiently.
        
        Batching is much more efficient for GPU processing as it allows
        parallel computation across all texts.
        
        Args:
            texts: List of texts to scan for PII
            language: Language code for analysis
            
        Returns:
            List of PIIFinding lists, one per input text
        """
        if not texts:
            return []
        
        try:
            # Use Presidio's batch analysis
            batch_results = self.analyzer.analyze_batch(
                texts=texts,
                entities=self.entities,
                language=language,
            )
            
            all_findings: list[list[PIIFinding]] = []
            
            for text, results in zip(texts, batch_results):
                findings: list[PIIFinding] = []
                for result in results:
                    if result.score >= self.score_threshold:
                        detected_text = text[result.start:result.end]
                        findings.append(PIIFinding(
                            entity_type=result.entity_type,
                            text=detected_text,
                            start=result.start,
                            end=result.end,
                            score=result.score,
                        ))
                all_findings.append(findings)
            
            return all_findings
            
        except AttributeError:
            # Older Presidio versions don't have analyze_batch
            # Fall back to sequential processing
            return [self.detect(text, language) for text in texts]
        except Exception:
            # Return empty findings for all texts on error
            return [[] for _ in texts]

