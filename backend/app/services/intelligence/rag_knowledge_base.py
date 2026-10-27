from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.user import KnowledgeDocument

class KnowledgeItem(BaseModel):
    doc_id: str
    category: str
    title: str
    content: str
    recommended_mitigation: str
    relevance_score: float # 0.0 to 1.0

# Curated defensive knowledge articles covering primary scam taxonomies
CURATED_DEFENSIVE_DOCS = [
    {
        "doc_id": "KB-CRED-001",
        "category": "credential_phishing",
        "title": "Account Suspension & Credential Harvesting Tactics",
        "keywords": "urgent,suspended,blocked,password,pin,otp,verify,login,security alert,unauthorized",
        "content": (
            "Attackers leverage urgent psychological triggers claiming immediate account suspension or unauthorized "
            "logins to induce panic. Victims are directed to lookalike authentication portals designed to steal login "
            "credentials, multi-factor authentication (MFA) tokens, or one-time passcodes."
        ),
        "recommended_mitigation": (
            "Never follow links in unsolicited security alerts. Navigate independently to the provider's verified official portal "
            "or mobile application. Enable hardware security keys (FIDO2/WebAuthn) rather than SMS-based MFA where possible."
        )
    },
    {
        "doc_id": "KB-BRAND-002",
        "category": "brand_impersonation",
        "title": "Lookalike Domain Spoofing & Typosquatting",
        "keywords": "paypal,apple,chase,microsoft,amazon,bank,spoof,domain,lookalike,impersonation,punycode",
        "content": (
            "Adversaries register domains incorporating recognized brand names, hyphenated variations, or non-standard TLDs "
            "(e.g., .xyz, .top, .live). Advanced variants use Punycode/IDN homoglyph substitution to visually imitate trusted brands."
        ),
        "recommended_mitigation": (
            "Inspect the fully qualified domain name (FQDN). Verify the root domain and top-level domain match official registries. "
            "Look for deceptive subdomains and unusual punctuation in URLs."
        )
    },
    {
        "doc_id": "KB-QR-003",
        "category": "qr_fraud",
        "title": "QR Code Phishing (Quishing) & Direct Transfer Risks",
        "keywords": "qr,quishing,matrix,camera,scan,payment,bitcoin,crypto,upi,wallet",
        "content": (
            "Quishing attacks utilize QR codes on physical posters, parking meters, or phishing emails to bypass email gateway "
            "URL scanners. Scanning may redirect the victim to credential harvesting sites or trigger immediate financial debit protocols."
        ),
        "recommended_mitigation": (
            "Avoid scanning QR codes in unverified emails or unsolicited paper notices. Verify the decoded destination URL preview "
            "before accepting navigation. Never authorize payment transactions directly from an unexpected QR prompt."
        )
    },
    {
        "doc_id": "KB-DELV-004",
        "category": "delivery_impersonation",
        "title": "Smishing Postal & Package Delivery Fee Scams",
        "keywords": "usps,dhl,ups,package,delivery,customs,fee,tracking,reschedule,postal",
        "content": (
            "Scammers send automated SMS messages masquerading as courier services (USPS, DHL, UPS) claiming an undeliverable "
            "package due to an incomplete address or small unpaid customs fee ($1-$5). The fake fee collection page harvests credit card details."
        ),
        "recommended_mitigation": (
            "Track shipments only via the merchant's original order dashboard or official postal websites using original tracking numbers. "
            "Legitimate postal agencies do not demand payment via random shortlinks sent by text."
        )
    },
    {
        "doc_id": "KB-FIN-005",
        "category": "financial_fraud",
        "title": "High-Yield Investment & Cryptocurrency Schemes",
        "keywords": "crypto,bitcoin,investment,guaranteed return,profit,lottery,inheritance,windfall,wire transfer",
        "content": (
            "Fraudulent investment schemes promise guaranteed high returns, algorithmic trading profits, or claim uncollected lottery "
            "prizes. Victims are persuaded to deposit cryptocurrency or wire funds to non-reversible accounts."
        ),
        "recommended_mitigation": (
            "Treat any promise of guaranteed financial returns or unsolicited prize notifications as fraudulent. Transactions on "
            "cryptocurrency blockchains and wire networks are permanent and generally non-recoverable."
        )
    }
]

def seed_knowledge_base_if_needed(db: Session):
    """Initializes the defensive scam intelligence knowledge base with curated records."""
    count = db.query(KnowledgeDocument).count()
    if count == 0:
        for doc in CURATED_DEFENSIVE_DOCS:
            kb = KnowledgeDocument(
                doc_id=doc["doc_id"],
                category=doc["category"],
                title=doc["title"],
                content=doc["content"],
                recommended_mitigation=doc["recommended_mitigation"],
                keywords=doc["keywords"],
                created_at=datetime.utcnow()
            )
            db.add(kb)
        db.commit()

def query_rag_knowledge_base(
    db: Session,
    query_text: str,
    limit: int = 3
) -> List[KnowledgeItem]:
    """
    RAG Retrieval Service:
    Scores and retrieves relevant defensive cybersecurity articles based on token matching and category relevance.
    Deterministic: Does not invent facts; retrieves verified defensive advisories.
    """
    seed_knowledge_base_if_needed(db)
    
    docs = db.query(KnowledgeDocument).all()
    q_tokens = set(query_text.lower().split())
    scored_items = []
    
    for d in docs:
        kw_tokens = set(d.keywords.lower().split(','))
        overlap = q_tokens.intersection(kw_tokens)
        
        # Calculate relevance score based on token density and overlap
        score = min(float(len(overlap)) / max(len(kw_tokens), 1) * 3.0, 1.0)
        
        # Check title overlap
        title_tokens = set(d.title.lower().split())
        title_overlap = q_tokens.intersection(title_tokens)
        if title_overlap:
            score = min(score + 0.35, 1.0)
            
        if score > 0.05:
            scored_items.append((score, d))
            
    # Sort descending by relevance score
    scored_items.sort(key=lambda x: x[0], reverse=True)
    
    results: List[KnowledgeItem] = []
    for sc, d in scored_items[:limit]:
        results.append(
            KnowledgeItem(
                doc_id=d.doc_id,
                category=d.category,
                title=d.title,
                content=d.content,
                recommended_mitigation=d.recommended_mitigation,
                relevance_score=round(sc, 2)
            )
        )
        
    return results
