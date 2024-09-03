use std::{collections::HashMap, fs, str::FromStr, sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex}, thread, time::Instant};

use snarkvm::prelude::{Address, MainnetV0, PrivateKey, Process, Program, TestRng, ValueType};
use snarkvm::synthesizer::program::StackProgram;

type CurrentAleo = snarkvm::circuit::network::AleoV0;

fn main() {
    let start = Instant::now();

    let errors: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let processed_count = Arc::new(AtomicUsize::new(0));

    let mut rng = TestRng::fixed(7777777);
    let private_key = PrivateKey::<MainnetV0>::new(&mut rng).unwrap();
    let burner_private_key = PrivateKey::new(&mut rng).unwrap();
    let burner_address = Address::try_from(&burner_private_key).unwrap();

    let path = std::env::args().nth(1).unwrap();

    let processed_count_ = processed_count.clone();
    let builder = thread::Builder::new().stack_size(2 * 1024 * 1024);
    let handler = builder.spawn(move || {
        let locked_process = Mutex::new(Process::load().unwrap());

        let errors_ = errors.clone();
        std::panic::set_hook(Box::new(move |panic_info| {
            let location = panic_info.location().unwrap().to_string();
            *errors_.lock().unwrap().entry(location).or_default() += 1;
        }));

        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();

            if entry.path().is_file() {
                let file_path = entry.path();
                let file_name = file_path.file_name().unwrap().to_string_lossy().into_owned();
                if file_name == "README.txt" {
                    continue;
                }

                processed_count_.fetch_add(1, Ordering::Relaxed);

                // let id = if file_name.starts_with("id") {
                //     file_name.truncate(9);
                //     let id = &file_name[3..];
                //     let id = id.trim_start_matches('0');
                //     u32::from_str_radix(id, 10).unwrap_or(0)
                // } else {
                //     unreachable!();
                // };

                // process an input
                if std::panic::catch_unwind(|| {
                    let file = fs::read(entry.path()).unwrap();
                    let program_string = String::from_utf8(file).unwrap();

                    let program = Program::<MainnetV0>::from_str(&program_string).unwrap();

                    if locked_process.is_poisoned() {
                        locked_process.clear_poison();
                    }
                    let mut process = locked_process.lock().unwrap();
                    process.reset();
                    process.add_program(&program).unwrap();

                    // traverse the functions
                    for function in program.functions().values() {
                        let function_name = function.name();

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
                            .collect::<Result<Vec<_>, _>>().unwrap();

                        let _auth = process.authorize::<CurrentAleo, _>(
                            &private_key, 
                            program.id(), 
                            function_name, 
                            inputs.into_iter(), 
                            &mut rng
                        ).unwrap();

                        // let _ = process.execute::<CurrentAleo, _>(auth, &mut rng);
                    }

                    (program, program_string)
                }).is_ok() {
                    println!("found a good program???");
                };
            }
        }

        println!();
        let mut errors = errors.lock().unwrap().iter().map(|(s, c)| (s.clone(), *c)).filter(|(_, count)| *count > 1).collect::<Vec<_>>();
        errors.sort_unstable_by_key(|(_, count)| std::cmp::Reverse(*count));
        for (e, count) in errors {
            println!("{e}: {count}");
        }
    }).unwrap();

    handler.join().unwrap();

    println!("\nprocessed {} crashes in {:?}", processed_count.load(Ordering::Relaxed), start.elapsed());
}
