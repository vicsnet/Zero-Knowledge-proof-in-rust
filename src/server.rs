use num_bigint::BigUint;
use std::{collections::HashMap, sync::Mutex};
use kp::ZKP;
use tonic::{transport::Server, Code, Request, Response, Status};
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthentcationChallengeResponse, AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    AutheticationAnswerResponse, RegisterRequest, RegisterResponse,
};

#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info:Mutex< HashMap<String, UserInfo>>,
    pub auth_id_to_user:Mutex< HashMap<String, String>>,
}

#[derive(Debug, Default)]
pub struct UserInfo {
    // registration
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,

    // authorization
    pub r1: BigUint,
    pub r2: BigUint,

    // verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
println!("Processing Register: {:?}", request);
        let request = request.into_inner();
        let user_name = request.user;
        let y1 = BigUint::from_bytes_be(&request.y1);
        let y2 = BigUint::from_bytes_be(&request.y2);

        let mut user_info = UserInfo::default();
        user_info.user_name = user_name.clone();
        user_info.y1 = y1;
        user_info.y2 = y2;
        
        let  mut user_info_hashmap = &mut self.user_info.lock().unwrap();
        user_info_hashmap.insert(user_name, user_info);

        Ok(Response::new(RegisterResponse{}))
    }
    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthentcationChallengeResponse>, Status> {
        println!("Processing challege request {:?}", request);
        let request = request.into_inner();
         let user_name = request.user;

         let mut user_info_hashmap = &mut self.user_info.lock().unwrap();
         
         if let Some(user_info) = user_info_hashmap.get_mut(&user_name){
             user_info.r1 = BigUint::from_bytes_be(&request.r1);
             user_info.r2 = BigUint::from_bytes_be(&request.r2);
             
             let(_,_,_,q) = ZKP::get_constants();
             let c = ZKP::generate_random_number_below(&q);
             let auth_id = ZKP::generate_random_string(12);
             user_info.c = c.clone();
             user_info.r1 = BigUint::from_bytes_be(&request.r1);
             user_info.r2 = BigUint::from_bytes_be(&request.r2);

             let mut auth_id_to_user = &mut self.auth_id_to_user.lock().unwrap();
             auth_id_to_user.insert(auth_id.clone(), user_name);

            Ok(Response::new(AuthentcationChallengeResponse{auth_id, c: c.to_bytes_be()}))
         }else{
            Err(Status::new(Code::NotFound, format!("User: {} not found in database", user_name)))
         }

        
    }
    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AutheticationAnswerResponse>, Status> {
        println!("Processing Verification {:?}", request);
        
        let request = request.into_inner();

        let auth_id = request.auth_id;
        let mut auth_id_to_user_hashmap = &mut self.auth_id_to_user.lock().unwrap();

        if let Some(user_name) = auth_id_to_user_hashmap.get_mut(&auth_id){
            let mut user_info_hashmap = &mut self.user_info.lock().unwrap();
            let user_info = user_info_hashmap.get_mut(user_name).expect("AuthId not found on hashMap");

            let s = BigUint::from_bytes_be(&request.s);
            let (alpha,beta,p,q) = ZKP::get_constants();
            let zkp = ZKP{alpha, beta, p, q};
            let verification = zkp.verify(&user_info.r1, &user_info.r2, &user_info.y1, &user_info.y2, &user_info.c, &s);

            if verification{

                let session_id = ZKP::generate_random_string(12);
                Ok(Response::new(AutheticationAnswerResponse {session_id}))
            }
            else{

                Err(Status::new(Code::PermissionDenied, format!("Auth Id: {} send a bad solution to the verifier", auth_id)))
            }


        } else{
            Err(Status::new(Code::NotFound, format!("Auth Id: {} not found in database", auth_id)))
        }
    }
}
#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();
    println!("Running the server in {}", addr);

    let auth_impl = AuthImpl::default();

    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("could not convert address"))
        .await
        .unwrap();
}
