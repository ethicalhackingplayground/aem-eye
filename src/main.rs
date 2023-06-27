use std::{collections::HashMap, error::Error, time::Duration};

use clap::{App, Arg};
use futures::{stream::FuturesUnordered, StreamExt};
use governor::{Quota, RateLimiter};
use regex::Regex;
use reqwest::redirect;
use tokio::{
    runtime::Builder,
    task,
};

use async_std::io;
use async_std::io::prelude::*;

#[derive(Clone, Debug)]
pub struct Job {
    ip_str: Option<String>,
    patterns: Option<HashMap<i32, String>>,
}

#[derive(Clone, Debug)]
pub struct JobResult {
    pub data: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // parse the cli arguments
    let matches = App::new("aem-eye")
        .version("0.1.8")
        .author("Blake Jacobs <krypt0mux@gmail.com>")
        .about("really fast aem detection tool")
        .arg(
            Arg::with_name("rate")
                .short('r')
                .long("rate")
                .takes_value(true)
                .default_value("1000")
                .display_order(2)
                .help("Maximum in-flight requests per second"),
        )
        .arg(
            Arg::with_name("concurrency")
                .short('c')
                .long("concurrency")
                .default_value("100")
                .takes_value(true)
                .display_order(3)
                .help("The amount of concurrent requests"),
        )
        .arg(
            Arg::with_name("timeout")
                .short('t')
                .long("timeout")
                .default_value("3")
                .takes_value(true)
                .display_order(4)
                .help("The delay between each request"),
        )
        .arg(
            Arg::with_name("workers")
                .short('w')
                .long("workers")
                .default_value("1")
                .takes_value(true)
                .display_order(5)
                .help("The amount of workers"),
        )
        .get_matches();

    let rate = match matches.value_of("rate").unwrap().parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            println!("{}", "could not parse rate, using default of 1000");
            1000
        }
    };

    let concurrency = match matches.value_of("concurrency").unwrap().parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            println!("{}", "could not parse concurrency, using default of 100");
            100
        }
    };

    let timeout = match matches.get_one::<String>("timeout").map(|s| s.to_string()) {
        Some(timeout) => timeout.parse::<usize>().unwrap(),
        None => 3,
    };

    let w: usize = match matches.value_of("workers").unwrap().parse::<usize>() {
        Ok(w) => w,
        Err(_) => {
            println!("{}", "could not parse workers, using default of 1");
            1
        }
    };

    let mut patterns = HashMap::new();
    patterns.insert(1, String::from(r"/content/dam.*"));
    patterns.insert(2, String::from(r"/etc.clientlibs.*"));

    // Set up a worker pool with the number of threads specified from the arguments
    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(w)
        .build()
        .unwrap();

    // job channels
    let (job_tx, job_rx) = spmc::channel::<Job>();

    rt.spawn(async move { send_url(job_tx, patterns, rate).await });

    // process the jobs
    let workers = FuturesUnordered::new();

    // process the jobs for scanning.
    for _ in 0..concurrency {
        let jrx = job_rx.clone();
        workers.push(task::spawn(async move {
            //  run the detector
            run_detector(jrx, timeout).await
        }));
    }
    let _: Vec<_> = workers.collect().await;
    rt.shutdown_background();

    Ok(())
}

async fn send_url(
    mut tx: spmc::Sender<Job>,
    patterns: HashMap<i32, String>,
    rate: u32,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    // send the jobs
    let stdin = io::BufReader::new(io::stdin());
    let mut lines = stdin.lines();
    while let Some(line) = lines.next().await {
        lim.until_ready().await;
        let host_line = line.unwrap();
        let mut host = String::from("");
        let url = match reqwest::Url::parse(&host_line) {
            Ok(url) => url,
            Err(_) => continue,
        };
        host.push_str(url.scheme());
        host.push_str("://");
        let host_str = match url.host_str() {
            Some(host_str) => host_str,
            None => continue,
        };
        host.push_str(host_str);
        let msg = Job {
            ip_str: Some(host.to_string().clone()),
            patterns: Some(patterns.clone()),
        };
        if let Err(_) = tx.send(msg) {
            continue;
        }
    }
    Ok(())
}

// this function will test perform the aem detection
pub async fn run_detector(rx: spmc::Receiver<Job>, timeout: usize) {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
        ),
    );

    //no certs
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(redirect::Policy::limited(10))
        .timeout(Duration::from_secs(timeout.try_into().unwrap()))
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    while let Ok(job) = rx.recv() {
        let job_host = job.ip_str.unwrap();
        let job_patterns = job.patterns.unwrap();
        for pattern in job_patterns {
            let job_host_new = job_host.clone();
            let get = client.get(job_host_new);
            let req = match get.build() {
                Ok(req) => req,
                Err(_) => {
                    continue;
                }
            };
            let resp = match client.execute(req).await {
                Ok(resp) => resp,
                Err(_) => {
                    continue;
                }
            };
            let body = match resp.text().await {
                Ok(body) => body,
                Err(_) => {
                    continue;
                }
            };

            let re = Regex::new(&pattern.1).unwrap();
            if re.is_match(&body) {
                println!("{}", job_host);
                continue;
            }
        }
    }
}
