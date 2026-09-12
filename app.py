from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

app = FastAPI()


@app.get("/")
def home():
    return PlainTextResponse("Privat Økonomi backend kører")


@app.get("/callback")
def callback():
    return PlainTextResponse("Enable Banking callback modtaget")
