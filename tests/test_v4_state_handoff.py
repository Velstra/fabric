"""Source wiring guards; real kernel fault injection is a separate test."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StateHandoffWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = (ROOT / "velstra-ebpf/src/main.rs").read_text()
        cls.agent = (ROOT / "velstra-app/src/firewall.rs").read_text()

    def test_no_flow_capacity_change(self):
        # Slot 0: the state stage; slot 1: its verdict stage.
        self.assertIn("V4_STATE_PROGS: ProgramArray = ProgramArray::with_max_entries(2, 0)", self.packet)
        self.assertIn("V4_STATE_SCRATCH: PerCpuArray<V4StateScratch>", self.packet)
        self.assertIn("V4_VERDICT: PerCpuArray<V4Verdict>", self.packet)
        for struct in ("V4StateScratch", "V4Verdict"):
            handoff = self.packet.split(f"struct {struct} {{", 1)[1].split("}", 1)[0]
            self.assertNotIn("*const", handoff, struct)
            self.assertNotIn("*mut", handoff, struct)

    def test_consumed_before_any_packet_action(self):
        stage = self.packet.split("pub fn velstra_v4_state(", 1)[1].split("/// IPv6 firewall tail", 1)[0]
        consumed = stage.index("write_volatile(&raw mut (*scratch).valid, 0)")
        self.assertLess(consumed, stage.index("let s ="))
        self.assertLess(consumed, stage.index("try_velstra_v4_state("))
        for guard in ("valid != 1", "before != epoch::snapshot()", "!epoch::unchanged(before)",
                      "!configuration_ready()", "!ha_permits(", "s.ifindex !=", "s.frame_len !="):
            self.assertIn(guard, stage)
        self.assertIn("ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN > ctx.data_end()", stage)
        self.assertIn("ctx.data() + EthHdr::LEN + s.ihl_bytes as usize > ctx.data_end()", stage)
        self.assertIn("s.total_len < s.ihl_bytes", stage)
        self.assertIn("EthHdr::LEN as u64 + s.total_len as u64 > s.frame_len", stage)

    def test_publication_is_last_and_missing_stage_drops(self):
        prefix = self.packet.split("fn try_velstra(ctx:", 1)[1].split("fn try_velstra_v4_state(", 1)[0]
        tail = prefix.split("write_volatile(&raw mut (*scratch).valid, 1);", 1)[1]
        self.assertTrue(tail.lstrip().startswith("V4_STATE_PROGS.tail_call(ctx, 0);"))
        self.assertIn("reset_v4_state();", tail)
        self.assertIn("Ok(xdp_action::XDP_DROP)", tail)
        self.assertNotIn("XDP_PASS", tail)
        main = self.packet.split("pub fn velstra_main(ctx:", 1)[1]
        self.assertLess(main.index("reset_v4_state();"), main.index("ha_permits("))

    def test_registered_and_verified_before_attach(self):
        registered = self.agent.index('(0, "velstra_v4_state",')
        ingress = self.agent.index('program_mut("velstra")', registered)
        setup = self.agent[registered:ingress]
        self.assertIn('(1, "velstra_v4_verdict",', setup)
        self.assertIn("program_mut(name)", setup)
        self.assertIn('map_mut("V4_STATE_PROGS")', setup)
        self.assertIn("programs.set(slot, &fd, 0)?;", setup)
        verification = self.agent.split("pub fn verify_object(", 1)[1].split("let exit:", 1)[0]
        self.assertIn('"velstra_v4_state",', verification)
        self.assertIn('"velstra_v4_verdict",', verification)

    def test_verdict_consumed_before_any_packet_action(self):
        stage = self.packet.split("pub fn velstra_v4_verdict(", 1)[1].split(
            "fn try_velstra_v4_verdict(", 1)[0]
        consumed = stage.index("write_volatile(&raw mut (*slot).ready, 0)")
        self.assertLess(consumed, stage.index("let v ="))
        self.assertLess(consumed, stage.index("try_velstra_v4_verdict("))
        for guard in ("ready != 1", "before != epoch::snapshot()", "!epoch::unchanged(before)",
                      "!configuration_ready()", "!ha_permits(", "v.ifindex !=", "v.frame_len !=",
                      "v.counter >= Counter::COUNT",
                      "ctx.data() + EthHdr::LEN + v.ihl_bytes as usize > ctx.data_end()"):
            self.assertIn(guard, stage)

    def test_verdict_publication_is_last_and_missing_stage_drops(self):
        stage = self.packet.split("fn try_velstra_v4_state(", 1)[1].split("struct V4Verdict {", 1)[0]
        self.assertLess(stage.index("observe("), stage.index("V4_VERDICT.get_ptr_mut(0)"))
        tail = stage.split("write_volatile(&raw mut (*slot).ready, 1);", 1)[1]
        self.assertTrue(tail.lstrip().startswith("V4_STATE_PROGS.tail_call(ctx, V4_VERDICT_SLOT);"))
        self.assertIn("Ok(xdp_action::XDP_DROP)", tail)
        self.assertNotIn("XDP_PASS", tail)

    def test_pure_verdict_reorder_keeps_frozen_operands_and_effect_order(self):
        stage = self.packet.split("fn try_velstra_v4_state(", 1)[1].split(
            "/// Tail-call target for the IPv4 forwarding transforms", 1
        )[0]
        read = stage.index("let has_port_forward = port_forward_exists(")
        for field in ("src_addr", "dst_addr", "proto", "src_port", "dst_port",
                      "total_len", "cfg", "blocklisted", "rule"):
            self.assertIn(f"let {field} = s.{field}", stage[:read])
        self.assertNotIn("s.total_len", stage[read:])
        self.assertIn("PacketMeta::new(src_addr, dst_addr, proto, src_port, dst_port, total_len)", stage)
        self.assertIn("decide(&meta, &cfg, blocklisted, rule_action)", stage)
        order = ["port_forward_exists(", "ct_key4(", "ct_router_normalize(", "ct_control(",
                 "synproxy_cfg(", "ct_classify(", "icmp_related::take_xdp(",
                 "let verdict = decide(", "rate_limits_allow(", "ct_record(",
                 "ct_record_wire4(", "observe("]
        offsets = [stage.index(call) for call in order]
        self.assertEqual(offsets, sorted(offsets))


if __name__ == "__main__":
    unittest.main()
