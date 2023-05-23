use migration::Migrator;
use sea_orm_migration::*;

#[async_std::main]
async fn main() {
    cli::run_cli(Migrator).await;
}
