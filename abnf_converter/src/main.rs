use std::{collections::HashSet, fs};

use abnf::{
    rulelist,
    types::{Node, Repeat, Rule, TerminalValues},
};

const NESTED_RULE_START: char = '（';
const NESTED_RULE_END: char = '）';

fn add_missing_body_brackets(body: String) -> String {
    if !body.starts_with('[') {
        format!("[{body}]")
    } else {
        body
    }
}

// TODO: rename to reflect that it also includes repetitions
fn extract_nested_grups_from_rules(rules: &[Rule]) -> Vec<Node> {
    let mut ret = Vec::new();
    for node in rules.iter().map(|r| r.node()) {
        extract_nested_groups_from_node(node, &mut ret);
    }
    ret
}

fn extract_nested_groups_from_node(node: &Node, ret: &mut Vec<Node>) {
    match node {
        Node::Alternatives(nodes) | Node::Concatenation(nodes) => {
            nodes
                .iter()
                .for_each(|n| extract_nested_groups_from_node(n, ret));
        }
        Node::Repetition { repeat: _, node: n } => {
            ret.push(node.clone());
            extract_nested_groups_from_node(n, ret);
        }
        Node::Group(n) => {
            ret.push(node.clone());
            extract_nested_groups_from_node(n, ret);
        }
        Node::Optional(n) => {
            ret.push(node.clone());
            extract_nested_groups_from_node(n, ret);
        }
        Node::TerminalValues(tv) if matches!(tv, TerminalValues::Range(..)) => {
            ret.push(node.clone());
        }
        _ => {}
    }
}

fn repetition_rule_name(node: &Node, toplevel: bool) -> String {
    let Node::Repetition { repeat, node } = node else {
        unreachable!();
    };

    let mut plural = true;
    let prefix = match repeat {
        Repeat::Specific(n) => {
            format!("{n}")
        }
        Repeat::Variable { min, max } => {
            if let (Some(min), Some(max)) = (min, max) {
                format!("between-{min}-and-{max}")
            } else if let Some(min) = min {
                if *min == 1 {
                    plural = false;
                }
                format!("at-least-{min}")
            } else if let Some(max) = max {
                if *max == 1 {
                    plural = false;
                }
                format!("at-most-{max}")
            } else {
                format!("zero-or-more")
            }
        }
    };
    let rule_name = json_rule_name_from_group(&*node, toplevel);
    if matches!(&**node, Node::Group(..) | Node::Repetition { .. }) {
        plural = false;
    }

    format!("{prefix}-{rule_name}{}", if plural { "s" } else { "" })
}

fn json_rule_name_from_group(node: &Node, toplevel: bool) -> String {
    let mut ret = String::new();
    match node {
        Node::Alternatives(nodes) => {
            if !toplevel {
                ret.push(NESTED_RULE_START);
            }
            let mut node_iter = nodes.iter().peekable();
            while let Some(node) = node_iter.next() {
                let name = json_rule_name_from_group(node, false);
                ret.push_str(&name);
                if node_iter.peek().is_some() {
                    ret.push_str("-or-");
                }
            }
            if !toplevel {
                ret.push(NESTED_RULE_END);
            }
        }
        Node::Concatenation(nodes) => {
            if !toplevel {
                ret.push(NESTED_RULE_START);
            }
            let mut node_iter = nodes.iter().peekable();
            while let Some(node) = node_iter.next() {
                let name = json_rule_name_from_group(node, false);
                ret.push_str(&name);
                if node_iter.peek().is_some() {
                    ret.push_str("-and-");
                }
            }
            if !toplevel {
                ret.push(NESTED_RULE_END);
            }
        }
        node @ Node::Repetition { .. } => {
            if !toplevel {
                ret.push(NESTED_RULE_START);
            }
            ret.push_str(&repetition_rule_name(node, false));
            if !toplevel {
                ret.push(NESTED_RULE_END);
            }
        }
        Node::Rulename(rule) => {
            ret.push_str(&rule);
        }
        Node::Group(node) => {
            ret.push_str(&json_rule_name_from_group(&*node, toplevel));
        }
        Node::Optional(node) => {
            ret.push_str(&format!(
                "optional-{}",
                json_rule_name_from_group(node, false)
            ));
        }
        Node::String(s) => {
            ret.push_str(s.as_str());
        }
        Node::TerminalValues(tv) => match tv {
            TerminalValues::Range(start, end) => {
                if !toplevel {
                    ret.push(NESTED_RULE_START);
                }
                ret.push_str(&format!("b{start}-to-b{end}"));
                if !toplevel {
                    ret.push(NESTED_RULE_END);
                }
            }
            TerminalValues::Concatenation(cs) => {
                if !toplevel {
                    ret.push(NESTED_RULE_START);
                }
                let mut val_iter = cs.iter().copied().peekable();
                while let Some(val) = val_iter.next() {
                    let c = char::from_u32(val).unwrap();
                    let s = format!("{:?}", c.to_string());
                    ret.push_str(&s);

                    if val_iter.peek().is_some() {
                        ret.push_str("-and-");
                    }
                }
                if !toplevel {
                    ret.push(NESTED_RULE_END);
                }
            }
        },
        _ => unimplemented!(),
    }

    ret.retain(|c| c != '.');
    let ret = ret.replace("_", "underscore");
    let ret = ret.replace("--", "-minus");

    ret
}

fn json_rule_body_from_group(
    main_node: &Node,
    rules: &[Rule],
    extra_nodes: &[Node],
    toplevel: bool,
) -> String {
    let mut ret = String::new();

    if !toplevel && extra_nodes.contains(main_node) {
        ret.push_str(&format!(
            "\"<{}>\"",
            json_rule_name_from_group(main_node, true)
        ));
        return ret;
    }

    match main_node {
        Node::Alternatives(nodes) => {
            let mut node_iter = nodes.iter().peekable();
            while let Some(node) = node_iter.next() {
                let name = format!(
                    "[{}]",
                    json_rule_body_from_group(node, rules, extra_nodes, false)
                );
                ret.push_str(&name);
                if node_iter.peek().is_some() {
                    ret.push_str(", ");
                }
            }
        }
        Node::Concatenation(nodes) => {
            let mut node_iter = nodes.iter().peekable();
            while let Some(node) = node_iter.next() {
                let name = format!(
                    "{}",
                    json_rule_body_from_group(node, rules, extra_nodes, false)
                );
                ret.push_str(&name);
                if node_iter.peek().is_some() {
                    ret.push_str(", ");
                }
            }
        }
        Node::Repetition { repeat, node } => match repeat {
            Repeat::Specific(n) => {
                let single = json_rule_body_from_group(&*node, rules, extra_nodes, false);
                ret.push('[');
                for i in 0..*n {
                    ret.push_str(&format!("{single}"));
                    if i < n - 1 {
                        ret.push_str(", ");
                    }
                }
                ret.push(']');
            }
            Repeat::Variable { min, max } => {
                if let (Some(_min), Some(_max)) = (min, max) {
                    unimplemented!();
                } else if let Some(min) = min {
                    let single = json_rule_body_from_group(&*node, rules, extra_nodes, false);
                    ret.push('[');
                    for i in 0..*min {
                        ret.push_str(&format!("{single}"));
                        if i < *min - 1 {
                            ret.push_str(", ");
                        }
                    }
                    let more = json_rule_name_from_group(main_node, false);
                    let rest = format!("], [{single}, \"<{more}>\"]");
                    ret.push_str(&rest);
                } else if let Some(max) = max {
                    ret.push_str("[], ");
                    let single = json_rule_body_from_group(&*node, rules, extra_nodes, false);
                    for i in 0..*max {
                        ret.push('[');
                        for j in 0..(i + 1) {
                            ret.push_str(&format!("{single}"));
                            if j < i {
                                ret.push_str(", ");
                            }
                        }
                        ret.push(']');
                        if i < *max - 1 {
                            ret.push_str(", ");
                        }
                    }
                } else {
                    let single = json_rule_body_from_group(&*node, rules, extra_nodes, false);
                    let more = json_rule_body_from_group(main_node, rules, extra_nodes, false);
                    let rest = format!("[], [{single}, {more}]");
                    ret.push_str(&rest);
                }
            }
        },
        Node::Rulename(rule) => {
            ret.push_str(&format!("\"<{rule}>\""));
        }
        Node::Group(node) => {
            ret.push_str(&format!(
                "{}",
                json_rule_body_from_group(&*node, rules, extra_nodes, false)
            ));
        }
        Node::Optional(node) => {
            ret.push_str(&format!(
                "[], [{}]",
                json_rule_body_from_group(node, rules, extra_nodes, false)
            ));
        }
        Node::String(s) => {
            let s = if s.as_str() == "\\" {
                format!("\"\\{}\"", s.as_str())
            } else {
                format!("\"{}\"", s.as_str())
            };
            ret.push_str(&s);
        }
        Node::TerminalValues(tv) => match tv {
            TerminalValues::Range(start, end) => {
                let mut val_iter = (*start..=*end).peekable();
                while let Some(val) = val_iter.next() {
                    let c = char::from_u32(val).unwrap();
                    let s = format!("[{:?}]", c.to_string());
                    ret.push_str(&s);

                    if val_iter.peek().is_some() {
                        ret.push_str(", ");
                    }
                }
            }
            TerminalValues::Concatenation(cs) => {
                let mut val_iter = cs.iter().copied().peekable();
                while let Some(val) = val_iter.next() {
                    let c = char::from_u32(val).unwrap();
                    let s = format!("[{:?}]", c.to_string());
                    ret.push_str(&s);

                    if val_iter.peek().is_some() {
                        ret.push_str(", ");
                    }
                }
            }
        },
        _ => unimplemented!(),
    }
    ret
}

fn extract_rules_for_nested_groups(rules: &[Rule], extra_nodes: &[Node]) -> String {
    let mut ret = String::new();

    let start_rule = format!("\"<start>\": [[\"program\"]]");
    ret.push_str(&format!("  {start_rule},\n"));

    if extra_nodes.is_empty() {
        return ret;
    }

    let mut known_rule_names = HashSet::new();
    for node in extra_nodes {
        let rule_name = json_rule_name_from_group(&node, true);
        if !known_rule_names.insert(rule_name.clone()) {
            continue;
        }
        let body = json_rule_body_from_group(&node, rules, &extra_nodes, true);
        let body = add_missing_body_brackets(body);
        let rule = format!("\"<{rule_name}>\": [{body}]");
        ret.push_str(&format!("  {rule},\n"));
    }
    ret
}

fn ruleset_to_json(rules: &[Rule]) -> String {
    let mut ret = String::new();
    ret.push_str("{\n");

    let extra_nodes = extract_nested_grups_from_rules(rules);

    ret.push_str(&extract_rules_for_nested_groups(rules, &extra_nodes));
    let mut rule_iter = rules.iter().peekable();
    while let Some(rule) = rule_iter.next() {
        ret.push_str(&rule_to_json(rule, &rules, &extra_nodes));

        if rule_iter.peek().is_some() {
            ret.push_str(", \n");
        }
    }
    ret.push_str("\n}");
    ret
}

fn rule_to_json(rule: &Rule, rules: &[Rule], extra_nodes: &[Node]) -> String {
    let name = rule.name();
    let body = json_rule_body_from_group(rule.node(), rules, extra_nodes, false);
    let body = add_missing_body_brackets(body);
    format!("  \"<{name}>\": [{body}]")
}

fn main() {
    let abnf_str = fs::read_to_string("/home/ljedrz/downloads/aleo_simplified.abnf").unwrap();
    let abnf_rules = rulelist(&abnf_str).unwrap();
    let json = ruleset_to_json(&abnf_rules);
    println!("{json}");
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_RULESET: &str = r#"
a = "a";
b = "b";
c = "c";

grp-a-any-bc = a ( b / c );
grp-a-all-bc = a ( b c );

nested-any-grp = a ( b / (a / c) );
nested-all-grp = a ( b (a c) );

star-a = *a;
one-star-a = 1*a;
star-two-a = *2a;
one-star-two-a = 1*2a;
"#;

    // println!("{json}");

    #[test]
    fn nested_group_extraction() {
        let rules = rulelist(SIMPLE_RULESET).unwrap();

        let extra_nodes = extract_nested_grups_from_rules(&rules);
        assert_eq!(extra_nodes.len(), 10);

        let mut node_iter = extra_nodes.iter();
        let node0 = node_iter.next().unwrap();
        assert_eq!("b-or-c", json_rule_name_from_group(node0, true));
        assert_eq!(
            "[\"<b>\"], [\"<c>\"]",
            json_rule_body_from_group(node0, &rules, &extra_nodes, true)
        );

        let node1 = node_iter.next().unwrap();
        assert_eq!("b-and-c", json_rule_name_from_group(node1, true));
        assert_eq!(
            "\"<b>\", \"<c>\"",
            json_rule_body_from_group(node1, &rules, &extra_nodes, true)
        );

        let node2 = node_iter.next().unwrap();
        assert_eq!("b-or-（a-or-c）", json_rule_name_from_group(node2, true));
        assert_eq!(
            "[\"<b>\"], [\"<a-or-c>\"]",
            json_rule_body_from_group(node2, &rules, &extra_nodes, true)
        );

        let node3 = node_iter.next().unwrap();
        assert_eq!("a-or-c", json_rule_name_from_group(node3, true));
        assert_eq!(
            "[\"<a>\"], [\"<c>\"]",
            json_rule_body_from_group(node3, &rules, &extra_nodes, true)
        );

        let node4 = node_iter.next().unwrap();
        assert_eq!("b-and-（a-and-c）", json_rule_name_from_group(node4, true));
        assert_eq!(
            "\"<b>\", \"<a-and-c>\"",
            json_rule_body_from_group(node4, &rules, &extra_nodes, true)
        );

        let node5 = node_iter.next().unwrap();
        assert_eq!("a-and-c", json_rule_name_from_group(node5, true));
        assert_eq!(
            "\"<a>\", \"<c>\"",
            json_rule_body_from_group(node5, &rules, &extra_nodes, true)
        );
    }

    #[test]
    fn repetitions() {
        let rules = rulelist(SIMPLE_RULESET).unwrap();

        let rep = rules.iter().find(|&r| r.name() == "star-a").unwrap().node();
        assert_eq!(repetition_rule_name(rep, true), "zero-or-more-as");

        let rep = rules
            .iter()
            .find(|&r| r.name() == "one-star-a")
            .unwrap()
            .node();
        assert_eq!(repetition_rule_name(rep, true), "at-least-1-a");

        let rep = rules
            .iter()
            .find(|&r| r.name() == "star-two-a")
            .unwrap()
            .node();
        assert_eq!(repetition_rule_name(rep, true), "at-most-2-as");

        let rep = rules
            .iter()
            .find(|&r| r.name() == "one-star-two-a")
            .unwrap()
            .node();
        assert_eq!(repetition_rule_name(rep, true), "between-1-and-2-as");
    }
}
