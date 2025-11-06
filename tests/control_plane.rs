use multicast_relay::{ForwardingRule, RelayCommand};
use tokio::sync::mpsc;

#[tokio::test]
async fn test_control_plane_logic() {
    let (relay_command_tx, mut relay_command_rx) = mpsc::channel(100);

    let rule = ForwardingRule {
        input_interface: "eth0".to_string(),
        input_group: "224.0.0.1".parse().unwrap(),
        input_port: 5000,
        outputs: vec![],
        dtls_enabled: false,
    };

    let add_cmd = RelayCommand::AddRule(rule.clone());
    relay_command_tx.send(add_cmd).await.unwrap();

    let received = relay_command_rx.recv().await;
    assert!(received.is_some());
}
