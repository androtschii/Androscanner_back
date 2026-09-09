from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from app.models import Role, ScanProfile, ScanStatus

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """Страница результатов.

    `total` нужен фронтенду, чтобы нарисовать «5 из 137» и понять, есть ли
    следующая страница. Без него он мог бы только гадать по длине списка.
    """

    items: list[T]
    total: int
    limit: int
    offset: int


# ---- Auth ----
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---- Users ----
MIN_PASSWORD_LENGTH = 10


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    # Минимум длины вместо требований к «сложности»: длина даёт больше
    # стойкости, чем обязательная заглавная буква и спецсимвол (NIST 800-63B)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=128)
    role: Role = Role.viewer


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: Role
    is_active: bool
    created_at: datetime


class PasswordChange(BaseModel):
    # Текущий пароль обязателен: иначе перехваченный токен позволял бы
    # сменить пароль и запереть владельца снаружи
    current_password: str
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=128)


# ---- Scopes ----
class ScopeCreate(BaseModel):
    cidr: str
    description: str = ""


class ScopeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cidr: str
    description: str


# ---- Scans ----
class ScanCreate(BaseModel):
    target: str
    profile: ScanProfile = ScanProfile.quick


class ScanSummary(BaseModel):
    """Для списка сканов. Без result: он весит килобайты на каждый скан,
    а списку не нужен."""

    model_config = ConfigDict(from_attributes=True)
    id: int
    target: str
    profile: ScanProfile
    status: ScanStatus
    created_by: int
    created_at: datetime


class ScanOut(ScanSummary):
    """Для карточки скана — с полным результатом."""

    result: str | None = None


# ---- Аналитика ----
class NamedCount(BaseModel):
    name: str
    count: int


class AnalyticsSummary(BaseModel):
    scans_total: int
    scans_by_status: list[NamedCount]
    scans_by_profile: list[NamedCount]
    hosts_unique: int
    open_ports_total: int
    top_services: list[NamedCount]
    top_ports: list[NamedCount]


# ---- Сравнение сканов ----
class PortBrief(BaseModel):
    port: int
    protocol: str
    service: str = ""


class HostWithPorts(BaseModel):
    ip: str
    ports: list[PortBrief]


class ServiceChange(BaseModel):
    port: int
    protocol: str
    before: str
    after: str


class HostChange(BaseModel):
    ip: str
    ports_opened: list[PortBrief]
    ports_closed: list[PortBrief]
    services_changed: list[ServiceChange]


class DiffSummary(BaseModel):
    hosts_added: int
    hosts_removed: int
    ports_opened: int
    ports_closed: int
    hosts_changed: int


class ScanDiff(BaseModel):
    base: ScanSummary
    compare: ScanSummary
    hosts_added: list[HostWithPorts]
    hosts_removed: list[HostWithPorts]
    host_changes: list[HostChange]
    summary: DiffSummary


# ---- Карта сети ----
class NetworkHost(BaseModel):
    ip: str
    hostnames: list[str]
    mac: str | None = None
    vendor: str | None = None
    os: str | None = None
    open_ports: int
    services: list[str]
    last_seen: str


class NetworkGroup(BaseModel):
    cidr: str
    description: str = ""
    hosts: list[NetworkHost]


class NetworkTotals(BaseModel):
    hosts: int
    networks: int
    open_ports: int


class NetworkMap(BaseModel):
    networks: list[NetworkGroup]
    ungrouped: list[NetworkHost]
    totals: NetworkTotals


# ---- Audit ----
class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    user_id: int | None
    action: str
    detail: str
    created_at: datetime
