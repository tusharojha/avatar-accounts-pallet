#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::*;


#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type WeightInfo: WeightInfo;
	}

	#[pallet::storage]
	pub type Something<T> = StorageValue<_, u32>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		
		SomethingStored {
			
			something: u32,
			
			who: T::AccountId,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		NoneValue,
		
    StorageOverflow,

    InvalidSignature
	}

  #[pallet::storage]
  pub type Nonces<T: Config> = StorageMap<_, Blake2_128Concat, T::EthereumAddress, T::Nonce, ValueQuery>;

  impl<T: Config> Pallet<T> {
    // Helper function to generate a keyless account
    fn generate_keyless_account(evm_address: &T::EthereumAddress) -> T::AccountId {
      let mut data = b"evm:".to_vec();
      data.extend_from_slice(&evm_address.encode());
      let hash = BlakeTwo256::hash(&data);
      
      // Convert the hash to AccountId
      T::AccountId::decode(&mut hash.as_ref())
          .expect("32 bytes can always be decoded to AccountId")
    }

    fn encode_packed(value: &[u8]) -> Vec<u8> {
      // For a string, we need to hash its UTF-8 encoding
        keccak_256(value).to_vec()
    }

    fn hash_domain() -> [u8; 32] {
        // Construct and hash the domain separator
        let domain_type_hash = keccak_256(b"EIP712Domain(uint256 chainId)");
        // let chain_id: U256 = 84532;
        let encoded_chain_id = U256::from(84532).encode();
        
        keccak_256(&[
            &domain_type_hash[..],
            &keccak_256(&encoded_chain_id)[..],
        ].concat())
    }

    fn get_final_hash(calls_hash: &[u8; 32]) -> [u8; 32] {
       // Construct the domain separator
       let domain_separator = Self::hash_domain();

       // Hash the type
       let type_hash = keccak_256(b"Swamp(string calls_hash)");

       // Hash the message
       let message_hash = &calls_hash;

       log::info!(target: "verify_signature", "message hash V:{:?}", message_hash.clone());

       // Construct the struct hash
       let struct_hash = keccak_256(&[
           &type_hash[..],
           &message_hash[..],
       ].concat());


      log::info!(target: "verify_signature", "domain_separator V:{:?}", domain_separator.clone());

      log::info!(target: "verify_signature", "struct_hash Hash V:{:?}", struct_hash.clone());
       // Construct the final hash
       let final_hash = keccak_256(&[
           b"\x19\x01",
           &domain_separator[..],
           &struct_hash[..],
       ].concat());

       final_hash
    }

    fn recover_signer(calls_hash: &[u8; 32], signature_g: &[u8; 65]) -> Option<H160> {
      let mut evm_addr = H160::default();
      log::info!(target: "verify_signature", "Calls Hash V:{:?}", calls_hash.clone());
      let final_hash = Self::get_final_hash(calls_hash);

      log::info!(target: "verify_signature", "Final Hash V:{:?}", final_hash.clone());


      let public_key = secp256k1_ecdsa_recover(&signature_g, &final_hash)
          .map_err(|_| Error::<T>::InvalidSignature).ok()?;


      evm_addr.0.copy_from_slice(&keccak_256(&public_key)[12..]);

      Some(evm_addr)
    }

    // Helper function to verify the Ethereum signature
    fn verify_signature(message_hash: &[u8; 32], signature: &[u8; 65], expected_address: &T::EthereumAddress) -> bool {
      if let Some(recovered_address) = Self::recover_signer(message_hash, signature) {
        log::info!(target: "verify_signature", "Recovered EVM Address: {:?}", recovered_address.clone());
          recovered_address != (*expected_address).into()
      } else {
          false
      }
    }
  }

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn do_something(origin: OriginFor<T>, something: u32) -> DispatchResult {
			let who = ensure_signed(origin)?;

			omething::<T>::put(something);

			Self::deposit_event(Event::SomethingStored { something, who });

			
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::cause_error())]
		pub fn cause_error(origin: OriginFor<T>) -> DispatchResult {
			let _who = ensure_signed(origin)?;
      match Something::<T>::get() {
				
				None => Err(Error::<T>::NoneValue.into()),
				Some(old) => {
					let new = old.checked_add(1).ok_or(Error::<T>::StorageOverflow)?;
					
					Something::<T>::put(new);
					Ok(())
				},
			}
		}
	}
}
