"""Curated, offline country / city / dial-code data for customer forms.

The list is hand-tuned to:
- show Arabic country names (matches the rest of the admin UI),
- put featured Arab countries near the top in a stable order
  (Palestine is first by request — owner is launching here),
- carry an ISO-3166 alpha-2 code as the stable persistence key,
- carry an E.164 dial-code used to normalize WhatsApp/SMS numbers,
- carry a curated list of major cities for the featured countries
  (fallback: empty list → the front-end shows a free-text city field).

This is intentionally a self-contained module so we have zero external
runtime dependency. Add cities as needed.
"""
from __future__ import annotations

from typing import TypedDict


class CountryInfo(TypedDict):
    iso: str            # ISO-3166 alpha-2 (uppercase), persistence key
    name_ar: str        # Arabic display name
    dial: str           # E.164 dial-code WITH leading '+'
    cities: list[str]   # major cities (Arabic), empty = no curated list


# Featured/MENA countries — order matters for the picker.
FEATURED: list[CountryInfo] = [
    {
        "iso": "PS",
        "name_ar": "فلسطين",
        "dial": "+970",
        "cities": [
            "القدس", "رام الله", "البيرة", "نابلس", "الخليل", "بيت لحم",
            "جنين", "طولكرم", "قلقيلية", "أريحا", "سلفيت", "طوباس",
            "غزة", "خان يونس", "رفح", "دير البلح", "بيت حانون", "جباليا",
        ],
    },
    {
        "iso": "JO",
        "name_ar": "الأردن",
        "dial": "+962",
        "cities": [
            "عمّان", "إربد", "الزرقاء", "العقبة", "السلط", "المفرق",
            "الكرك", "معان", "جرش", "عجلون", "مادبا", "الطفيلة",
        ],
    },
    {
        "iso": "SA",
        "name_ar": "السعودية",
        "dial": "+966",
        "cities": [
            "الرياض", "جدة", "مكة المكرمة", "المدينة المنورة", "الدمام",
            "الخبر", "الظهران", "الطائف", "تبوك", "بريدة", "خميس مشيط",
            "الأحساء", "حائل", "نجران", "جازان", "أبها", "ينبع",
        ],
    },
    {
        "iso": "EG",
        "name_ar": "مصر",
        "dial": "+20",
        "cities": [
            "القاهرة", "الإسكندرية", "الجيزة", "شبرا الخيمة", "بورسعيد",
            "السويس", "المنصورة", "طنطا", "أسيوط", "الفيوم", "الزقازيق",
            "الإسماعيلية", "أسوان", "دمياط", "بني سويف", "المنيا",
            "سوهاج", "قنا", "الأقصر", "العاشر من رمضان",
        ],
    },
    {
        "iso": "AE",
        "name_ar": "الإمارات",
        "dial": "+971",
        "cities": [
            "دبي", "أبوظبي", "الشارقة", "العين", "عجمان", "رأس الخيمة",
            "الفجيرة", "أم القيوين",
        ],
    },
    {
        "iso": "KW",
        "name_ar": "الكويت",
        "dial": "+965",
        "cities": [
            "مدينة الكويت", "حولي", "الجهراء", "الفروانية", "مبارك الكبير",
            "الأحمدي", "السالمية",
        ],
    },
    {
        "iso": "QA",
        "name_ar": "قطر",
        "dial": "+974",
        "cities": ["الدوحة", "الريان", "الوكرة", "الخور", "أم صلال", "الشحانية"],
    },
    {
        "iso": "BH",
        "name_ar": "البحرين",
        "dial": "+973",
        "cities": ["المنامة", "المحرق", "الرفاع", "حمد", "عيسى", "سترة"],
    },
    {
        "iso": "OM",
        "name_ar": "عُمان",
        "dial": "+968",
        "cities": ["مسقط", "صلالة", "صحار", "نزوى", "صور", "البريمي", "إبراء"],
    },
    {
        "iso": "YE",
        "name_ar": "اليمن",
        "dial": "+967",
        "cities": ["صنعاء", "عدن", "تعز", "الحديدة", "إب", "المكلا", "ذمار"],
    },
    {
        "iso": "IQ",
        "name_ar": "العراق",
        "dial": "+964",
        "cities": [
            "بغداد", "البصرة", "الموصل", "أربيل", "السليمانية", "النجف",
            "كركوك", "كربلاء", "الناصرية", "الحلة", "الرمادي", "دهوك",
        ],
    },
    {
        "iso": "SY",
        "name_ar": "سوريا",
        "dial": "+963",
        "cities": ["دمشق", "حلب", "حمص", "حماة", "اللاذقية", "طرطوس", "دير الزور", "الرقة"],
    },
    {
        "iso": "LB",
        "name_ar": "لبنان",
        "dial": "+961",
        "cities": ["بيروت", "طرابلس", "صيدا", "صور", "زحلة", "جونية", "بعلبك"],
    },
    {
        "iso": "LY",
        "name_ar": "ليبيا",
        "dial": "+218",
        "cities": ["طرابلس", "بنغازي", "مصراتة", "البيضاء", "سبها", "طبرق", "زليتن"],
    },
    {
        "iso": "TN",
        "name_ar": "تونس",
        "dial": "+216",
        "cities": ["تونس", "صفاقس", "سوسة", "القيروان", "بنزرت", "قابس", "أريانة"],
    },
    {
        "iso": "DZ",
        "name_ar": "الجزائر",
        "dial": "+213",
        "cities": ["الجزائر", "وهران", "قسنطينة", "عنابة", "البليدة", "باتنة", "سطيف"],
    },
    {
        "iso": "MA",
        "name_ar": "المغرب",
        "dial": "+212",
        "cities": [
            "الدار البيضاء", "الرباط", "فاس", "مراكش", "أكادير", "طنجة",
            "مكناس", "وجدة", "تطوان", "سلا",
        ],
    },
    {
        "iso": "SD",
        "name_ar": "السودان",
        "dial": "+249",
        "cities": ["الخرطوم", "أم درمان", "بحري", "بورتسودان", "كسلا", "نيالا", "الأبيض"],
    },
    {
        "iso": "MR",
        "name_ar": "موريتانيا",
        "dial": "+222",
        "cities": ["نواكشوط", "نواذيبو", "روصو", "كيفة"],
    },
    {
        "iso": "SO",
        "name_ar": "الصومال",
        "dial": "+252",
        "cities": ["مقديشو", "هرجيسا", "كيسمايو", "بربرة"],
    },
    {
        "iso": "DJ",
        "name_ar": "جيبوتي",
        "dial": "+253",
        "cities": ["جيبوتي"],
    },
    {
        "iso": "KM",
        "name_ar": "جزر القمر",
        "dial": "+269",
        "cities": ["موروني"],
    },
]


# Remaining countries — sorted alphabetically by Arabic name at module level
# (handled at runtime). No curated city list — city becomes a free-text input.
OTHER: list[CountryInfo] = [
    {"iso": "IL", "name_ar": "إسرائيل (احتلال 1948)", "dial": "+972", "cities": []},
    {"iso": "TR", "name_ar": "تركيا",      "dial": "+90",  "cities": []},
    {"iso": "IR", "name_ar": "إيران",      "dial": "+98",  "cities": []},
    {"iso": "PK", "name_ar": "باكستان",    "dial": "+92",  "cities": []},
    {"iso": "AF", "name_ar": "أفغانستان",  "dial": "+93",  "cities": []},
    {"iso": "IN", "name_ar": "الهند",      "dial": "+91",  "cities": []},
    {"iso": "BD", "name_ar": "بنغلاديش",   "dial": "+880", "cities": []},
    {"iso": "ID", "name_ar": "إندونيسيا",  "dial": "+62",  "cities": []},
    {"iso": "MY", "name_ar": "ماليزيا",    "dial": "+60",  "cities": []},
    {"iso": "CN", "name_ar": "الصين",      "dial": "+86",  "cities": []},
    {"iso": "JP", "name_ar": "اليابان",    "dial": "+81",  "cities": []},
    {"iso": "KR", "name_ar": "كوريا الجنوبية", "dial": "+82", "cities": []},
    {"iso": "RU", "name_ar": "روسيا",      "dial": "+7",   "cities": []},
    {"iso": "UA", "name_ar": "أوكرانيا",   "dial": "+380", "cities": []},
    {"iso": "DE", "name_ar": "ألمانيا",    "dial": "+49",  "cities": []},
    {"iso": "FR", "name_ar": "فرنسا",      "dial": "+33",  "cities": []},
    {"iso": "GB", "name_ar": "المملكة المتحدة", "dial": "+44", "cities": []},
    {"iso": "IT", "name_ar": "إيطاليا",    "dial": "+39",  "cities": []},
    {"iso": "ES", "name_ar": "إسبانيا",    "dial": "+34",  "cities": []},
    {"iso": "NL", "name_ar": "هولندا",     "dial": "+31",  "cities": []},
    {"iso": "BE", "name_ar": "بلجيكا",     "dial": "+32",  "cities": []},
    {"iso": "SE", "name_ar": "السويد",     "dial": "+46",  "cities": []},
    {"iso": "NO", "name_ar": "النرويج",    "dial": "+47",  "cities": []},
    {"iso": "DK", "name_ar": "الدنمارك",   "dial": "+45",  "cities": []},
    {"iso": "FI", "name_ar": "فنلندا",     "dial": "+358", "cities": []},
    {"iso": "CH", "name_ar": "سويسرا",     "dial": "+41",  "cities": []},
    {"iso": "AT", "name_ar": "النمسا",     "dial": "+43",  "cities": []},
    {"iso": "PT", "name_ar": "البرتغال",   "dial": "+351", "cities": []},
    {"iso": "GR", "name_ar": "اليونان",    "dial": "+30",  "cities": []},
    {"iso": "PL", "name_ar": "بولندا",     "dial": "+48",  "cities": []},
    {"iso": "RO", "name_ar": "رومانيا",    "dial": "+40",  "cities": []},
    {"iso": "US", "name_ar": "الولايات المتحدة", "dial": "+1", "cities": []},
    {"iso": "CA", "name_ar": "كندا",       "dial": "+1",   "cities": []},
    {"iso": "MX", "name_ar": "المكسيك",    "dial": "+52",  "cities": []},
    {"iso": "BR", "name_ar": "البرازيل",   "dial": "+55",  "cities": []},
    {"iso": "AR", "name_ar": "الأرجنتين",  "dial": "+54",  "cities": []},
    {"iso": "AU", "name_ar": "أستراليا",   "dial": "+61",  "cities": []},
    {"iso": "NZ", "name_ar": "نيوزيلندا",  "dial": "+64",  "cities": []},
    {"iso": "ZA", "name_ar": "جنوب أفريقيا", "dial": "+27", "cities": []},
    {"iso": "NG", "name_ar": "نيجيريا",    "dial": "+234", "cities": []},
    {"iso": "KE", "name_ar": "كينيا",      "dial": "+254", "cities": []},
    {"iso": "ET", "name_ar": "إثيوبيا",    "dial": "+251", "cities": []},
    {"iso": "GH", "name_ar": "غانا",       "dial": "+233", "cities": []},
    {"iso": "TZ", "name_ar": "تنزانيا",    "dial": "+255", "cities": []},
    {"iso": "UG", "name_ar": "أوغندا",     "dial": "+256", "cities": []},
]


def _sorted_others() -> list[CountryInfo]:
    # Stable alpha sort by Arabic name (locale-aware best-effort; Python's
    # default sort is Unicode order which is good enough for the picker).
    return sorted(OTHER, key=lambda c: c["name_ar"])


def all_countries() -> list[CountryInfo]:
    """Picker order: featured (curated order) → rest (alphabetic)."""
    return list(FEATURED) + _sorted_others()


def country_by_iso(iso: str) -> CountryInfo | None:
    iso_u = (iso or "").strip().upper()
    if not iso_u:
        return None
    for c in FEATURED:
        if c["iso"] == iso_u:
            return c
    for c in OTHER:
        if c["iso"] == iso_u:
            return c
    return None


def cities_by_iso(iso: str) -> list[str]:
    info = country_by_iso(iso)
    return list(info["cities"]) if info else []


def dial_by_iso(iso: str) -> str:
    info = country_by_iso(iso)
    return info["dial"] if info else ""


def is_known_iso(iso: str) -> bool:
    return country_by_iso(iso) is not None


# Lookup maps for JS — emitted as a compact JSON-ish object in the template.
def picker_payload() -> dict:
    """Compact shape consumed by inline JS for dependent dropdowns.

    Keeps featured/other separation so the template can mark a divider, then
    flattens for client-side lookup.
    """
    rows = all_countries()
    return {
        "featured": [c["iso"] for c in FEATURED],
        "items": [
            {"iso": c["iso"], "name_ar": c["name_ar"], "dial": c["dial"], "cities": c["cities"]}
            for c in rows
        ],
    }
