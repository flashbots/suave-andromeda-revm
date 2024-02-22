use anyhow::Result;
use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::Response;
use reqwest::Url;
use serde::Serialize;
use serde::de::DeserializeOwned;
use reqwest::header::HeaderValue;
use reqwest::header::{ACCEPT, AUTHORIZATION};

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PostBody {
    body: String,
}

impl PostBody {
    pub fn from_string(body: String) -> Self {
        Self {
            body,
        }
    }
}

pub struct Client {
    client: HttpClient,
}

impl Client {
    pub fn new() -> Result<Client> {
        Ok(Client {
            client: HttpClient::builder().cookie_store(true).build()?,
        })
    }

    pub fn get(&self, url: String) -> Result<Response> {
        let zurl = Url::parse(&url)?;

        self.client
            .get(zurl)
            .send()?
            .error_for_status()
            .map_err(|e| e.into())
    }

    pub fn post<I, O>(&self, url: String, body: &I, token: Option<&str>) -> Result<O, reqwest::Error>
        where I: Serialize, O: DeserializeOwned
    {
        let zurl = Url::parse(&url).expect("url parse");
        let json = HeaderValue::from_static("application/json");
        match token{
            Some(atoken) =>             self.client.post(zurl).json(body).header(ACCEPT, &json).header(AUTHORIZATION, atoken).send()?.error_for_status()?.json(),
            None =>  self.client.post(zurl).json(body).header(ACCEPT, &json).send()?.error_for_status()?.json(),

        }

    }
}
