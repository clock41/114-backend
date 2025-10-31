from typing import Annotated ,List ,Union
from fastapi import FastAPI, Body,Path,Cookie,Form
from pydantic import BaseModel, Field

class Item(BaseModel):
    name: str
    description: str | None = Field(
        default=None, title="The description of the item",max_lenght=300
    )
    price: float = Field(gt=0, description="The price must be greater than zero")
    tax : Union[float,None] = None
    tags : list[str] = []

app=FastAPI()

@app.port("/login")
async def login(
    username: Annotated[str, Ｆorm()],
    password: Annotated[str, Ｆorm()],
):
    return {"username": username }

@app.get("/")
async def root():
    return {"messge":"Hello world"}

@app.get("/item/{item_id}")
async def read_item(item_id):
    return {"item_id":item_id}
'''
@app.get("/items/")
async def read_item(skip: int =0, limit: int=10):
    return fake_item_db[skip : skip+limit]

fake_item_db = [
    {"item_id": "Foo"},
    {"item_id": "Bar"},
    {"item_id": "Baz"}
]
'''
@app.get("/items/")
async def read_items(ads_id: Annotated[str | None, Cookie()]) :
    return {"ads_id": ads_id}

@app.post("/items/")
async def create_item(item: Item) -> Item:
    return Item
'''
    item_dict = item.model_dump() # item.dict()
    if item.tax is not None:
        price_with_tax = item.price+item.tax
        item_dict.update({"price_with_tax": price_with_tax})
    return item_dict
'''
'''
@app.put("/item/{item_id}")
async def update_item(
                        item_id: Annotated [int, Path(title="The ID of the item to get",ge=0,le=1000)],
                       item: Item| None=None,
                       q: str | None=None ,
    ):
    results = {"item_id":item_id}
    if q:
        results.updata({"q":q})
    if item:
        results.updata({"item":item})
    return results
'''
@app.put("/item/{item_id}")
async def update_item(item_id: int, item: Annotated[Item, Body(embed=True)]):
    results = {"item_id": item_id,"item":item}
    return results