// Generated from SDK immutable schemas by generate-schema.mjs; do not edit.
pub(crate) struct Schema {
 pub fixed:bool, pub identities:usize, pub accumulators:usize, pub quotient:usize,
 pub domain:&'static str, pub input_bytes:usize, pub output_bytes:usize,
}
static S1:Schema=Schema{fixed:false,identities:66,accumulators:64,quotient:188,domain:"406435817742925408890100530791791433588437037312",input_bytes:864,output_bytes:32480};
static S2:Schema=Schema{fixed:true,identities:66,accumulators:64,quotient:152,domain:"407173916385039488777917032230477238504980361472",input_bytes:960,output_bytes:31328};
static S3:Schema=Schema{fixed:false,identities:67,accumulators:65,quotient:115,domain:"26636177751600359597021628385971156694668806978941184",input_bytes:864,output_bytes:30528};
static S4:Schema=Schema{fixed:true,identities:67,accumulators:65,quotient:108,domain:"406435817740251192357087807242550169024528265472",input_bytes:960,output_bytes:30304};
static S5:Schema=Schema{fixed:true,identities:68,accumulators:66,quotient:76,domain:"1587639913047856220144874247109043781673300224",input_bytes:960,output_bytes:29664};
static S6:Schema=Schema{fixed:false,identities:68,accumulators:66,quotient:94,domain:"406435817742925408890100530792079663938818945280",input_bytes:864,output_bytes:30240};
pub(crate) fn get(id:u8)->&'static Schema{match id{1=>&S1,2=>&S2,3=>&S3,4=>&S4,5=>&S5,6=>&S6,_=>panic!("unknown schema")}}
