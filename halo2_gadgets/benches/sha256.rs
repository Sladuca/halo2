use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::{pallas, EqAffine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
        SingleVerifier,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::rngs::OsRng;

use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};

use criterion::{criterion_group, criterion_main, Criterion};

use halo2_gadgets::sha256::{BlockWord, Table16Chip, Table16Config, Sha256Instructions};

#[allow(dead_code)]
fn bench(name: &str, k: u32, c: &mut Criterion) {
    #[derive(Default, Copy, Clone)]
    struct MyCircuit;

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = Vec<Table16Config>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            (0..15).map(|_| Table16Chip::configure(meta)).collect::<Vec<_>>()
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            // load 16 instances of the "table16" chip into the circuit
            for (i, chip_config) in config.into_iter().enumerate() {
                Table16Chip::load(chip_config.clone(), &mut layouter)?;
                let table16_chip = Table16Chip::construct(chip_config);
    
                // Test vector: "abc"
                let block = [
                    BlockWord(Value::known(0b01100001011000100110001110000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000000000)),
                    BlockWord(Value::known(0b00000000000000000000000000011000)),
                ];
                let state = table16_chip.initialization_vector(&mut layouter)?;
                table16_chip.compress(&mut layouter.namespace(|| format!("compression {}", i)), &state, block)?;
            }

            Ok(())
        }
    }

    let mut group = c.benchmark_group("sha256");
    group.sample_size(10);

    // Initialize the polynomial commitment parameters
    let params_path = Path::new("./benches/sha256_assets/sha256_params");
    if File::open(&params_path).is_err() {
        let params: Params<EqAffine> = Params::new(k);
        let mut buf = Vec::new();

        params.write(&mut buf).expect("Failed to write params");
        let mut file = File::create(&params_path).expect("Failed to create sha256_params");

        file.write_all(&buf[..])
            .expect("Failed to write params to file");
    }

    let params_fs = File::open(&params_path).expect("couldn't load sha256_params");
    let params: Params<EqAffine> =
        Params::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    let empty_circuit: MyCircuit = MyCircuit;

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let circuit: MyCircuit = MyCircuit;

    let prover_name = name.to_string() + "-prover";
    let verifier_name = name.to_string() + "-verifier";

    // Benchmark proof creation
    // group.bench_function(&prover_name, |b| {
    //     b.iter(|| {
    //         let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    //         create_proof(&params, &pk, &[circuit], &[], OsRng, &mut transcript)
    //             .expect("proof generation should not fail");
    //         let _proof: Vec<u8> = transcript.finalize();
    //     });
    // });

    // Create a proof
    let proof_path = Path::new("./benches/sha256_assets/sha256_proof");
    if File::open(&proof_path).is_err() {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(&params, &pk, &[circuit], &[], OsRng, &mut transcript)
            .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();
        let mut file = File::create(&proof_path).expect("Failed to create sha256_proof");
        file.write_all(&proof[..]).expect("Failed to write proof");
    }

    let mut proof_fs = File::open(&proof_path).expect("couldn't load sha256_proof");
    let mut proof = Vec::<u8>::new();
    proof_fs
        .read_to_end(&mut proof)
        .expect("Couldn't read proof");

    group.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(&params, pk.get_vk(), strategy, &[], &mut transcript).is_ok());
        });
    });

    group.finish();
}

#[allow(dead_code)]
fn criterion_benchmark(c: &mut Criterion) {
    bench("sha256", 17, c);
    // bench("sha256", 20, c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
