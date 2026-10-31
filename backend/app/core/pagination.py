"""Pagination and sorting helpers shared by list endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import Query
from pydantic import BaseModel, Field
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

MAX_PAGE_SIZE = 200


class PageParams(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=MAX_PAGE_SIZE)

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def page_params(
    page: Annotated[int, Query(ge=1, description="1-based page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE, description="Items per page")] = 25,
) -> PageParams:
    return PageParams(page=page, page_size=page_size)


class Page[T](BaseModel):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int

    @classmethod
    def build(cls, items: list[T], total: int, params: PageParams) -> Page[T]:
        pages = (total + params.page_size - 1) // params.page_size if params.page_size else 0
        return cls(
            items=items,
            total=total,
            page=params.page,
            page_size=params.page_size,
            pages=pages,
        )


def paginate(db: Session, stmt: Select, params: PageParams) -> tuple[list, int]:
    """Execute ``stmt`` with LIMIT/OFFSET and return (rows, total_count)."""
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.limit(params.page_size).offset(params.offset)).scalars().all()
    return list(rows), int(total)


def apply_sort(
    stmt: Select,
    column_map: dict[str, object],
    sort_by: str | None,
    sort_order: str,
    default_column: object,
) -> Select:
    """Apply a whitelisted sort column; unknown columns fall back to default."""
    column = column_map.get(sort_by or "", default_column)
    if sort_order.lower() == "asc":
        return stmt.order_by(column.asc())  # type: ignore[attr-defined]
    return stmt.order_by(column.desc())  # type: ignore[attr-defined]
