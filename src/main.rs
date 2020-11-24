use algebra_core::{CanonicalDeserialize, CanonicalSerialize};
use groth16::Parameters as Groth16Parameters;
use bls_crypto::{PublicKey as BlsPubkey, Signature, hash_to_curve::try_and_increment::COMPOSITE_HASH_TO_G1, hash_to_curve::try_and_increment_cip22::COMPOSITE_HASH_TO_G1_CIP22};
use std::slice;


use epoch_snark::{trusted_setup, prove, verify, BLSCurve, EpochBlock, EpochTransition, Parameters};

use ethers_core::{types::U256, utils::rlp};
use ethers_providers::*;

use gumdrop::Options;
use std::{
    convert::TryFrom,
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
    sync::Arc,
};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

mod types;
use types::HeaderExtra;

#[derive(Debug, Options, Clone)]
pub struct PlumoOpts {
    help: bool,

    #[options(help = "the celo node's endpoint", default = "http://localhost:8545")]
    pub node_url: String,

    #[options(help = "the duration of an epoch (in blocks)", default = "17280")]
    pub epoch_duration: usize,

    #[options(help = "the first block in the range being proven")]
    pub start_block: u64,

    #[options(help = "the last block in the range being proven")]
    pub end_block: u64,

    #[options(help = "path to the proving key for the BLS SNARK")]
    pub epoch_proving_key: PathBuf,

    #[options(help = "path to the proving key for the CRH -> XOF SNARK")]
    pub hash_to_bits_proving_key: Option<PathBuf>,

    #[options(help = "path where the proof will be saved at")]
    pub proof_path: PathBuf,

    #[options(help = "the number of validators")]
    pub num_validators: u32,

    #[options(help = "the max allowed faults")]
    pub maximum_non_signers: u32,

    #[options(help = "the maximum number of validators", default = "150")]
    pub max_validators: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // initialize the logger
    Subscriber::builder()
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // parse the cli args
    let opts = PlumoOpts::parse_args_default_or_exit();
    // let maximum_non_signers = opts.maximum_non_signers;
    // let num_validators = opts.num_validators;

    let provider = Arc::new(Provider::<Http>::try_from("http://127.0.0.1:8545")?);

        let futs = (55u64..65)
            .step_by(1)
            .enumerate()
            .map(|(i, epoch_index)| {
                let provider = provider.clone();
                async move {
                    let epoch = 10;
                    let previous_num = (epoch_index-1)*epoch;
                    let num = epoch_index*epoch;
                    println!("nums: {}, {}", previous_num, num);

                    let block = provider.get_block(num).await.expect("could not get block");
                    let parent_block = provider.get_block(num - epoch).await.expect("could not get parent epoch block");
                    let previous_validators = provider.get_validators_bls_public_keys(format!("0x{:x}", previous_num+1)).await.expect("could not get validators");
                    let previous_validators_keys = previous_validators.into_iter().map(|s| BlsPubkey::deserialize(&mut hex::decode(&s[2..]).expect("Deserialize 1").as_slice())).collect::<Result<Vec<_>, _>>().expect("COllection 1");
                    let validators = provider.get_validators_bls_public_keys(format!("0x{:x}", num+1)).await.expect("could not get validators");
                    let validators_keys = validators.into_iter().map(|s| BlsPubkey::deserialize(&mut hex::decode(&s[2..]).expect("Second deserialize").as_slice())).collect::<Result<Vec<_>, _>>().expect("Collection");

                    let max_validators = 150;

                    // Get the bitmap / signature
                    let bitmap = {
                        let bitmap_num = U256::from(&block.epoch_snark_data.bitmap.0[..]);
                        let mut bitmap = Vec::new();
                        for i in 0..1 {
                            bitmap.push(bitmap_num.bit(i));
                        }
                        bitmap
                    };
                    // println!("bitmap: {:?}", bitmap);

                    let signature = block.epoch_snark_data.signature;
                    let aggregate_signature = Signature::deserialize(&mut &signature.0[..])
                        .expect("could not deserialize signature - your header snark data is corrupt");
                    // println!("Aggregated signature {:?}", aggregate_signature);

                    let block_hash = block.hash.unwrap();
                    let parent_hash = parent_block.hash.unwrap();
                    let entropy = unsafe { Some(slice::from_raw_parts(block_hash.as_ptr(), EpochBlock::ENTROPY_BYTES).to_vec()) };
                    let parent_entropy = unsafe { Some(slice::from_raw_parts(parent_hash.as_ptr(), EpochBlock::ENTROPY_BYTES).to_vec()) };
                    // println!("Entropy {:?}", entropy);
                    // println!("Parent Entropy {:?}", parent_entropy);

                    //for i in 0..100 {
                    let i = 0;
                        let epoch_block = EpochBlock {
                            index: epoch_index as u16,
                            round: 0,
                            epoch_entropy: entropy,
                            parent_entropy: parent_entropy,
                            maximum_non_signers: 0,
                            maximum_validators: max_validators,
                            new_public_keys: validators_keys.clone(),
                        };
                        println!("Epoch block {:?}", epoch_block);
                        // let bytes: &[u8];
                        // let extra_data;// = epoch_block.encode_inner_epoch_to_bytes_cip22().unwrap();
                        let (mut encoded_inner, mut encoded_extra_data) =
                                epoch_block.encode_inner_to_bytes_cip22().unwrap();
                        // unsafe {
                        //     *bytes = encoded_inner.as_mut_ptr();
                        //     *extra_data = encoded_extra_data.as_mut_ptr();
                        // }
                        let mut participating_keys = vec![];
                        for (j, b) in bitmap.iter().enumerate() {
                            if *b {
                                participating_keys.push(previous_validators_keys[j].clone());
                            }
                        }
                        let aggregated_key = BlsPubkey::aggregate(&participating_keys);
                        let res = aggregated_key.verify(
                            &encoded_inner,
                            &encoded_extra_data,
                            &aggregate_signature,
                            &*COMPOSITE_HASH_TO_G1_CIP22,
                        ).expect("AGgregated key verify");
                    //}
                    
                    // construct the epoch block transition
                    EpochTransition {
                        block: EpochBlock {
                            index: epoch_index as u16,
                            round: 0,
                            epoch_entropy: None,
                            parent_entropy: None,
                            maximum_non_signers: 0,
                            maximum_validators: max_validators,
                            new_public_keys: validators_keys,
                        },
                        aggregate_signature,
                        bitmap,
                    }
                }
            })
            .collect::<Vec<_>>();

    for epoch_index in 55u64..65 {
        println!("epoch {}", epoch_index);
    }

        let mut transitions = futures_util::future::join_all(futs).await;
        let first_epoch = transitions.remove(0).block;
        let last_epoch = transitions.iter().last().unwrap().block.clone();
        let num_transitions = 10;
        let num_validators = 1u32;
        println!("Running trusted setup");
        let epoch_proving_key = trusted_setup(num_validators as usize, num_transitions, 0, &mut rand::thread_rng(), false)
        .expect("Could not verify").epochs;
        println!("Finished trusted setup");

        let parameters = Parameters {
            epochs: epoch_proving_key,
            hash_to_bits: None,
        };
        let proof = prove(&parameters, num_validators, &first_epoch, &transitions, num_transitions)
            .expect("could not generate zkp");

        let mut file = BufWriter::new(File::create("./proof")?);
        proof.serialize(&mut file)?;

        println!("OK!");
        Ok(())

        // println!("firstEpoch {:?}\n num_validators: {:?}\n transitions {:?}\n lastEpoch: {:?}", first_epoch, num_validators, transitions, last_epoch);
        // let first_proof = prove(&parameters, num_validators, &first_epoch, &transitions[0..8], num_transitions)
        //     .expect("could not generate zkp");
        // let first_last_epoch = transitions.remove(7).block;
        // println!("First last epoch {:?}", first_last_epoch);
        // println!("Transition 6 {:?}", transitions[6]);
        // println!("TRansition 7 {:?}", transitions[7]);
        // println!("TRansition 8 {:?}", transitions[8]);
        // let second_proof = prove(&parameters, num_validators, &first_last_epoch, &transitions[7..], num_transitions)
        //     .expect("could not generate zkp");

        // verify(&parameters.epochs.vk, &first_epoch, &first_last_epoch, &first_proof).expect("Proof could not be verified");
        // verify(&parameters.epochs.vk, &first_last_epoch, &last_epoch, &second_proof).expect("Proof could not be verified");

        // let mut first_serialized_proof = vec![];
        // let mut second_serialized_proof = vec![];
        // let mut serialized_vk = vec![];
        // first_proof.serialize(&mut first_serialized_proof).unwrap();
        // second_proof.serialize(&mut second_serialized_proof).unwrap();
        // parameters.epochs.vk.serialize(&mut serialized_vk).unwrap();
        // dbg!(hex::encode(&serialized_vk));
        // dbg!(hex::encode(&first_serialized_proof));
        // dbg!(hex::encode(&second_serialized_proof));
        // // let mut file = BufWriter::new(File::create("./proof")?);
        // // proof.serialize(&mut file)?;

        // // let mut vk_file = BufWriter::new(File::create("./verification_key")?);
        // // parameters.epochs.vk.serialize(&mut vk_file)?;

        // println!("OK!");
        // Ok(())
}
