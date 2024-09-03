use std::{collections::HashMap, fs, path::PathBuf, str::FromStr, sync::Mutex, thread, time::Instant};

use anyhow::{anyhow, bail};
use rand::Rng;
use snarkvm::{
    circuit::network::AleoV0,
    prelude::{Address, MainnetV0, PrivateKey, Process, Program, TestRng, ValueType},
    synthesizer::program::StackProgram,
};

type CurrentAleo = AleoV0;
type CurrentNetwork = MainnetV0;

fn main() {
    let start = Instant::now();

    // reusable snarkvm objects
    let mut rng = TestRng::fixed(7777777);
    let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng).unwrap();
    let burner_private_key = PrivateKey::new(&mut rng).unwrap();
    let burner_address = Address::try_from(&burner_private_key).unwrap();
    let locked_process = Mutex::new(Process::load().unwrap());

    // register the arguments
    let corpus_path = PathBuf::from(std::env::args().nth(1).expect("missing corpus path param"));
    let out_path = PathBuf::from(std::env::args().nth(2).expect("missing output path param"));

    // prepare the collection of newfound seeds and errors
    let mut new_seeds: Vec<String> = Vec::new();
    let mut errors: HashMap<String, usize> = HashMap::new();

    // in case the stack is insufficient
    let builder = thread::Builder::new().stack_size(2 * 1024 * 1024);
    let handler = builder.spawn(move || {
        // traverse the corpus files
        let mut processed_count = 0;
        for entry in fs::read_dir(&corpus_path).unwrap() {
            let entry = entry.unwrap();
            if entry.path().is_file() {
                let file_path = entry.path();
                let file_name = file_path.file_name().unwrap().to_string_lossy().into_owned();

                // skip the readme
                if file_name == "README.txt" {
                    continue;
                }

                processed_count += 1;

                // process the corpus, catching any panics
                match std::panic::catch_unwind(|| {
                    // read the corpus file
                    let file = fs::read(entry.path()).unwrap();
                    let corpus_string = String::from_utf8(file).unwrap();

                    // reject entries that are barely different from the ones already saved
                    for seed in &new_seeds {
                        // an optimization to ignore files unlikely to be similar judging just by length
                        let size_comparison = seed.len() as f64 / corpus_string.len() as f64;
                        if size_comparison > 0.9 && size_comparison < 1.1 {
                            // check if the difference is meaningful
                            if strsim::normalized_damerau_levenshtein(&corpus_string, seed) > 0.9 {
                                anyhow::bail!("Copycat input");
                            }
                        }
                    }

                    // attempt to parse the corpus
                    let program = Program::<MainnetV0>::from_str(&corpus_string)
                        .map_err(|_| anyhow!("Parsing error"))?;

                    // reject corpus w/o functions
                    if program.functions().is_empty() {
                        bail!("No functions");
                    }

                    // reset the process
                    if locked_process.is_poisoned() {
                        locked_process.clear_poison();
                    }
                    let mut process = locked_process.lock().unwrap();
                    process.reset();

                    // attempt to add the corpus as a program
                    process.add_program(&program)?;

                    // traverse the functions in the corpus
                    for function in program.functions().values() {
                        let function_name = function.name();

                        // sample applicable inputs
                        let mut rng = TestRng::default();
                        let input_types = function.input_types();
                        let stack = process.get_stack(program.id()).unwrap();
                        let inputs = input_types
                            .iter()
                            .map(|input_type| match input_type {
                                ValueType::ExternalRecord(locator) => {
                                    let stack = stack.get_external_stack(locator.program_id())?;
                                    stack.sample_value(&burner_address, &ValueType::Record(*locator.resource()), &mut rng)
                                }
                                _ => {
                                    stack.sample_value(&burner_address, &input_type, &mut rng)
                                }
                            })
                            .collect::<Result<Vec<_>, _>>()?;

                        // attempt to authorize
                        let _auth = process.authorize::<CurrentAleo, _>(
                            &private_key, 
                            program.id(), 
                            function_name, 
                            inputs.into_iter(), 
                            &mut rng
                        )?;

                        // let _ = process.execute::<CurrentAleo, _>(auth, &mut rng);
                    }

                    Ok(corpus_string)
                }) {
                    Ok(Ok(corpus_string)) => {
                        // assign a random id to the new seed
                        let mut random_id: u64 = rng.gen();
                        let mut new_path = out_path.clone();
                        new_path.push(&random_id.to_string());
                        // ensure that the name is unique
                        while new_path.exists() {
                            random_id = rng.gen();
                            new_path.pop();
                            new_path.push(random_id.to_string());
                        }

                        // save the new seed to disk
                        fs::write(new_path, corpus_string.as_bytes()).unwrap();
                        // save the new seed to memory
                        new_seeds.push(corpus_string);

                    },
                    Ok(Err(e)) => {
                        // count any errors
                        let s = e.to_string();
                        let mut e = String::new();
                        let split = s.split('\'');
                        for (i, chunk) in split.enumerate() {
                            if i % 2 == 0 {
                                e.push_str(chunk);
                            } else {
                                e.push('X');
                            }
                        }
                        *errors.entry(e).or_default() += 1
                    },
                    _ => *errors.entry("PANICs".into()).or_default() += 1,
                };
            }
        }

        println!("\nfound {} prospect seeds\n", new_seeds.len());

        let mut errors = errors.into_iter().filter(|(_, count)| *count > 1).collect::<Vec<_>>();
        errors.sort_unstable_by_key(|(_, count)| std::cmp::Reverse(*count));
        println!("found the following errors:\n");
        for (e, count) in errors {
            println!("{e}: {count}");
        }

        processed_count
    }).unwrap();

    let processed_count = handler.join().unwrap();

    println!("\nprocessed {processed_count} corpus files in {:?}", start.elapsed());
}
