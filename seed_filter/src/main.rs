use std::{fs, hash::{Hash, Hasher}, path::PathBuf, str::FromStr, time::Instant};

use indexmap::IndexSet;
use snarkvm::{
    prelude::{Closure, EntryType, Finalize, Function, Instruction, MainnetV0, Mapping, Network, PlaintextType, Program, RecordType, StructType}, 
    synthesizer::program::{
        closure::{
            input::Input as ClosureInput,
            output::Output as ClosureOutput,
        },
        function::{
            input::Input as FunctionInput,
            output::Output as FunctionOutput,
        },
        finalize::input::Input as FinalizeInput,
    },
    synthesizer::Command
};

type CurrentNetwork = MainnetV0;

#[derive(PartialEq, Eq, Hash)]
struct FilteredMapping<N: Network>(PlaintextType<N>, PlaintextType<N>);

impl<N: Network> From<&Mapping<N>> for FilteredMapping<N> {
    fn from(m: &Mapping<N>) -> Self {
        Self(
            m.key().plaintext_type().clone(), 
            m.value().plaintext_type().clone()
        )
    }
}

#[derive(PartialEq, Eq, Hash)]
struct FilteredStruct<N: Network>(Vec<PlaintextType<N>>);

impl<N: Network + Ord> From<&StructType<N>> for FilteredStruct<N> {
    fn from(s: &StructType<N>) -> Self {
        let members = s.members().values().cloned().collect::<IndexSet<_>>();
        let mut members = members.into_iter().collect::<Vec<_>>();
        members.sort_unstable();

        Self(members)
    }
}

#[derive(PartialEq, Eq, Hash)]
struct FilteredRecord<N: Network>(Vec<EntryType<N>>);

impl<N: Network + Ord> From<&RecordType<N>> for FilteredRecord<N> {
    fn from(r: &RecordType<N>) -> Self {
        let entries = r.entries().values().cloned().collect::<IndexSet<_>>();
        let mut entries = entries.into_iter().collect::<Vec<_>>();
        entries.sort_unstable();

        Self(entries)
    }
}

#[derive(PartialEq, Eq, Hash)]
struct FilteredClosure<N: Network>{
    inputs: Vec<ClosureInput<N>>,
    instructions: Vec<Instruction<N>>,
    outputs: Vec<ClosureOutput<N>>,
}

impl<N: Network + Ord> From<&Closure<N>> for FilteredClosure<N> {
    fn from(c: &Closure<N>) -> Self {
        let mut inputs = c.inputs().iter().cloned().collect::<Vec<_>>();
        inputs.sort_unstable();

        let instructions = c.instructions().iter().cloned().collect::<IndexSet<_>>();
        let instructions = instructions.into_iter().collect::<Vec<_>>();
        
        let outputs = c.outputs().iter().cloned().collect::<Vec<_>>();
        // outputs.sort_unstable();

        Self { inputs, instructions, outputs }
    }
}

impl<N: Network> FilteredClosure<N> {
    fn score(&self) -> usize {
        self.inputs.len()
            + self.instructions.len()
            + self.outputs.len()
    }
}

#[derive(PartialEq, Eq, Hash)]
struct FilteredFunction<N: Network>{
    inputs: Vec<FunctionInput<N>>,
    instructions: Vec<Instruction<N>>,
    outputs: Vec<FunctionOutput<N>>,
    finalize: Option<FilteredFinalize<N>>,
}

impl<N: Network + Ord> From<&Function<N>> for FilteredFunction<N> {
    fn from(f: &Function<N>) -> Self {
        let mut inputs = f.inputs().iter().cloned().collect::<Vec<_>>();
        inputs.sort_unstable();

        let instructions = f.instructions().iter().cloned().collect::<IndexSet<_>>();
        let instructions = instructions.into_iter().collect::<Vec<_>>();
        
        let outputs = f.outputs().iter().cloned().collect::<Vec<_>>();
        // outputs.sort_unstable();

        let finalize = f.finalize_logic().map(|f| f.into());

        Self { inputs, instructions, outputs, finalize }
    }
}

impl<N: Network> FilteredFunction<N> {
    fn score(&self) -> usize {
        self.inputs.len()
            + self.instructions.len()
            + self.outputs.len()
            + self.finalize.as_ref().map(|f| f.score()).unwrap_or(0)
    }
}

#[derive(PartialEq, Eq, Hash)]
struct FilteredFinalize<N: Network> {
    inputs: Vec<FinalizeInput<N>>,
    commands: Vec<Command<N>>,
}

impl<N: Network + Ord> From<&Finalize<N>> for FilteredFinalize<N> {
    fn from(f: &Finalize<N>) -> Self {
        let inputs = f.inputs().iter().cloned().collect::<IndexSet<_>>();
        let mut inputs = inputs.into_iter().collect::<Vec<_>>();
        inputs.sort_unstable();

        let commands = f.commands().iter().cloned().collect::<IndexSet<_>>();
        let commands = commands.into_iter().collect::<Vec<_>>();
        
        Self { inputs, commands }
    }
}

impl<N: Network> FilteredFinalize<N> {
    fn score(&self) -> usize {
        1 + self.inputs.len() + self.commands.len()
    }
}

struct FilteredProgram<N: Network> {
    path: PathBuf,
    code: String,
    mappings: Vec<FilteredMapping<N>>,
    structs: Vec<FilteredStruct<N>>,
    records: Vec<FilteredRecord<N>>,
    closures: Vec<FilteredClosure<N>>,
    functions: Vec<FilteredFunction<N>>,
}

impl<N: Network + Ord> FilteredProgram<N> {
    fn load(path: PathBuf) -> Self {
        // read the seed file
        let file = fs::read(&path).unwrap();
        let code = String::from_utf8(file).unwrap();

        // parse the seed
        let program = Program::<N>::from_str(&code).unwrap();
        let code = program.to_string();

        let mappings = program.mappings().values().map(|m| m.into()).collect::<IndexSet<_>>();
        let mappings = mappings.into_iter().collect::<Vec<_>>();

        let structs = program.structs().values().map(|s| s.into()).collect::<IndexSet<_>>();
        let structs = structs.into_iter().collect::<Vec<_>>();

        let records = program.records().values().map(|r| r.into()).collect::<IndexSet<_>>();
        let records = records.into_iter().collect::<Vec<_>>();

        let closures = program.closures().values().map(|c| c.into()).collect::<IndexSet<_>>();
        let closures = closures.into_iter().collect::<Vec<_>>();

        let functions = program.functions().values().map(|f| f.into()).collect::<IndexSet<_>>();
        let functions = functions.into_iter().collect::<Vec<_>>();

        Self {
            path, 
            code, 
            mappings, 
            structs, 
            records, 
            closures, 
            functions,
        }
    }
}

impl<N: Network> PartialEq for FilteredProgram<N> {
    fn eq(&self, other: &Self) -> bool {
        self.mappings == other.mappings
            && self.structs == other.structs
            && self.records == other.records 
            && self.closures == other.closures 
            && self.functions == other.functions 
    }
}
impl<N: Network> Eq for FilteredProgram<N> {}

impl<N: Network> Hash for FilteredProgram<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mappings.hash(state);
        self.structs.hash(state);
        self.records.hash(state);
        self.closures.hash(state);
        self.functions.hash(state);
    }
}

impl<N: Network> FilteredProgram<N> {
    fn score(&self) -> usize {
        self.mappings.len()
            + self.structs.len() + self.structs.iter().map(|s| s.0.len()).sum::<usize>()
            + self.records.len() + self.records.iter().map(|r| r.0.len()).sum::<usize>()
            + self.closures.len() + self.closures.iter().map(|c| c.score()).sum::<usize>()
            + self.functions.len() + self.functions.iter().map(|f| f.score()).sum::<usize>()
    }
}

fn main() {
    let start = Instant::now();

    // register the arguments
    let original_seed_path = PathBuf::from(std::env::args().nth(1).expect("missing seed path param"));
    let prospect_seed_path = PathBuf::from(std::env::args().nth(2).expect("missing seed path param"));
    let out_path = PathBuf::from(std::env::args().nth(3).expect("missing output path param"));

    let mut unique_seeds: IndexSet<FilteredProgram<CurrentNetwork>> = Default::default();

    // remember the original seeds
    let mut original_seeds: IndexSet<FilteredProgram<CurrentNetwork>> = Default::default();
    for entry in fs::read_dir(&original_seed_path).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_file() {
            let file_path = entry.path();

            let seed = FilteredProgram::<MainnetV0>::load(file_path);
            original_seeds.insert(seed);
        }
    }

    // traverse the corpus files
    let mut processed_count = 0;
    for entry in fs::read_dir(&prospect_seed_path).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_file() {
            let file_path = entry.path();
            let file_name = file_path.file_name().unwrap().to_string_lossy().into_owned();

            let fp = FilteredProgram::<MainnetV0>::load(file_path.clone());

            if let Some(existing_seed) = unique_seeds.get(&fp) {
                if existing_seed.code.len() > fp.code.len() {
                    let mut new_path = out_path.clone();
                    new_path.push(file_name);
                    fs::write(new_path, fp.code.as_bytes()).unwrap();

                    unique_seeds.insert(fp);
                }
            } else {
                let mut new_path = out_path.clone();
                new_path.push(file_name);
                fs::write(new_path, fp.code.as_bytes()).unwrap();

                unique_seeds.insert(fp);
            }

            processed_count += 1;
        }
    }

    let new_unique_seeds = unique_seeds.difference(&original_seeds);

    let mut scores = Vec::with_capacity(unique_seeds.len());
    for seed in new_unique_seeds {
        let path = seed.path.clone();
        let score = seed.score();
        let code = seed.code.clone();

        scores.push((path, code, score));
    }
    scores.sort_unstable_by_key(|(_, _, score)| *score);
    scores.reverse();

    println!("\nmost interesting new seeds:\n");
    for (path, code, score) in scores.iter().take(10).rev() {
        println!("{} ({score} pts):\n{code}\n", path.display());
    }

    println!("found {} distinct seeds in the given list of {processed_count} in {:?}", 
        unique_seeds.len(), 
        start.elapsed(),
    );
}
