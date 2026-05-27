use super::model_runner::ModelRunner;

pub fn run_ai_self_test() -> anyhow::Result<()> {
    let runner = ModelRunner::load_default()?;
    runner.inference_smoke_test()
}
