use std::{collections::HashMap, error::Error, process::exit, time::Duration};

use clap::{App, Arg};
use futures::{stream::FuturesUnordered, StreamExt};
use governor::{Quota, RateLimiter};
use regex::Regex;
use reqwest::redirect;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
    runtime::Builder,
    sync::mpsc,
    task,
};

#[derive(Clone, Debug)]
pub struct Job {
    ip_str: Option<String>,
    patterns: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug)]
pub struct JobResult {
    pub data: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // parse the cli arguments
    let matches = App::new("aem-eye")
        .version("0.5.3")
        .author("Blake Jacobs <krypt0mux@gmail.com>")
        .about("really fas aem detection tool")
        .arg(
            Arg::with_name("hosts")
                .short('u')
                .long("hosts")
                .takes_value(true)
                .required(true)
                .help("the hosts you would like to test"),
        )
        .arg(
            Arg::with_name("rate")
                .short('r')
                .long("rate")
                .takes_value(true)
                .default_value("1000")
                .help("Maximum in-flight requests per second"),
        )
        .arg(
            Arg::with_name("concurrency")
                .short('c')
                .long("concurrency")
                .default_value("1000")
                .takes_value(true)
                .help("The amount of concurrent requests"),
        )
        .arg(
            Arg::with_name("timeout")
                .long("t")
                .default_value("10")
                .takes_value(true)
                .help("The delay between each request"),
        )
        .arg(
            Arg::with_name("workers")
                .short('w')
                .long("workers")
                .default_value("10")
                .takes_value(true)
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
            println!("{}", "could not parse concurrency, using default of 1000");
            1000
        }
    };

    let timeout = match matches.get_one::<String>("timeout").map(|s| s.to_string()) {
        Some(timeout) => timeout.parse::<usize>().unwrap(),
        None => 10,
    };

    let w: usize = match matches.value_of("workers").unwrap().parse::<usize>() {
        Ok(w) => w,
        Err(_) => {
            println!("{}", "could not parse workers, using default of 10");
            10
        }
    };

    let hosts_path = match matches.get_one::<String>("hosts").map(|s| s.to_string()) {
        Some(hosts_path) => hosts_path,
        None => "".to_string(),
    };

    let hosts_handle = match File::open(hosts_path).await {
        Ok(hosts_handle) => hosts_handle,
        Err(e) => {
            println!("failed to open input file: {:?}", e);
            exit(1);
        }
    };

    // construct the hosts from a vector of strings
    let mut hosts = vec![];
    let hosts_buf = BufReader::new(hosts_handle);
    let mut hosts_lines = hosts_buf.lines();
    while let Ok(Some(host)) = hosts_lines.next_line().await {
        hosts.push(host);
    }

    // Set up a worker pool with the number of threads specified from the arguments
    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(w)
        .build()
        .unwrap();

    // job channels
    let (job_tx, job_rx) = spmc::channel::<Job>();
    let (result_tx, _result_rx) = mpsc::channel::<JobResult>(w);

    let mut patterns = HashMap::new();
    patterns.insert(
        String::from("http_resp"),
        String::from(r#"href="\/content\/dam.*"#),
    );
    patterns.insert(
        String::from("http_resp"),
        String::from(r#"href="\/etc.clientlibs.*"#),
    );
    rt.spawn(async move { send_url(job_tx, hosts, patterns, rate).await });

    // process the jobs
    let workers = FuturesUnordered::new();

    // process the jobs for scanning.
    for _ in 0..concurrency {
        let jrx = job_rx.clone();
        let jtx: mpsc::Sender<JobResult> = result_tx.clone();
        workers.push(task::spawn(async move {
            //  run the detector
            run_detector(jrx, jtx, timeout).await
        }));
    }

    let _: Vec<_> = workers.collect().await;

    rt.shutdown_background();

    Ok(())
}

async fn send_url(
    mut tx: spmc::Sender<Job>,
    ip_strs: Vec<String>,
    patterns: HashMap<String, String>,
    rate: u32,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    // send the jobs
    for host in ip_strs.iter() {
        let msg = Job {
            ip_str: Some(host.clone()),
            patterns: Some(patterns.clone()),
        };
        if let Err(_) = tx.send(msg) {
            continue;
        }
        lim.until_ready().await;
    }
    Ok(())
}

// this function will test perform the aem detection
pub async fn run_detector(
    rx: spmc::Receiver<Job>,
    tx: mpsc::Sender<JobResult>,
    timeout: usize,
) -> JobResult {
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
            let job_host_result = job_host_new.clone();
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
                Err(_) => continue,
            };

            let re = Regex::new(&pattern.1).unwrap();
            for cap in re.captures_iter(&body) {
                if cap.len() > 0 {
                    println!("{}", job_host);
                    break;
                }
            }

            // send the result message through the channel to the workers.
            let result_msg = JobResult {
                data: job_host_result.to_owned(),
            };
            let result_job = result_msg.clone();
            if let Err(_) = tx.send(result_msg).await {
                continue;
            }
            return result_job;
        }
    }
    return JobResult {
        data: "".to_string(),
    };
}