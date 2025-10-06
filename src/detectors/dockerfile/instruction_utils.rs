//! Utilities for working with Dockerfile instructions.
//!
//! This module provides helper functions for extracting information from
//! Dockerfile instructions, converting them to searchable formats, and
//! calculating line numbers.

use dockerfile_parser::{Instruction, Stage};
use serde_yml::Value;
use std::collections::HashMap;

/// Extracts the instruction type as a string (e.g., "FROM", "RUN", "USER").
///
/// # Arguments
///
/// * `ins` - The instruction to identify
///
/// # Returns
///
/// A string representing the instruction type in uppercase
pub fn get_instruction_kind(ins: &Instruction) -> String {
    match ins {
        Instruction::From(_) => "FROM".to_string(),
        Instruction::Run(_) => "RUN".to_string(),
        Instruction::Cmd(_) => "CMD".to_string(),
        Instruction::Label(_) => "LABEL".to_string(),
        Instruction::Env(_) => "ENV".to_string(),
        Instruction::Copy(_) => "COPY".to_string(),
        Instruction::Entrypoint(_) => "ENTRYPOINT".to_string(),
        Instruction::Arg(_) => "ARG".to_string(),
        Instruction::Misc(m) => m.instruction.content.to_uppercase(),
    }
}

/// Converts an instruction to a key-value map for rule matching.
///
/// Different instruction types produce different fields:
/// - FROM: `from.tag`, `from.image`
/// - RUN/CMD/ENTRYPOINT: `command`
/// - ENV: `env.key`, `env.value`
/// - USER/EXPOSE/etc: instruction-specific fields
///
/// # Arguments
///
/// * `ins` - The instruction to convert
///
/// # Returns
///
/// A HashMap of field names to YAML values
pub fn instruction_to_map(ins: &Instruction) -> HashMap<String, Value> {
    let mut map = HashMap::new();

    match ins {
        Instruction::From(f) => {
            let tag = f.image_parsed.tag
                .clone()
                .unwrap_or_else(|| "latest".to_string());

            map.insert("from.tag".to_string(), Value::String(tag));
            map.insert("from.image".to_string(), Value::String(f.image_parsed.image.clone()));
        }
        Instruction::Run(r) => {
            let cmd = format!("{:?}", r.expr);
            map.insert("command".to_string(), Value::String(cmd));
        }
        Instruction::Cmd(c) => {
            let cmd = format!("{:?}", c.expr);
            map.insert("command".to_string(), Value::String(cmd));
        }
        Instruction::Entrypoint(e) => {
            let cmd = format!("{:?}", e.expr);
            map.insert("command".to_string(), Value::String(cmd));
        }
        Instruction::Env(e) => {
            if let Some(first) = e.vars.first() {
                map.insert("env.key".to_string(), Value::String(first.key.content.clone()));
                map.insert("env.value".to_string(), Value::String(first.value.to_string()));
            }
        }
        Instruction::Misc(m) => {
            let instruction_name = m.instruction.content.to_uppercase();
            let arguments = m.arguments.to_string();

            match instruction_name.as_str() {
                "USER" => {
                    map.insert("user".to_string(), Value::String(arguments.trim().to_string()));
                }
                "EXPOSE" => {
                    let port = arguments.split_whitespace().next().unwrap_or("").to_string();
                    map.insert("port".to_string(), Value::String(port));
                }
                "ADD" | "WORKDIR" | "VOLUME" => {
                    map.insert("arguments".to_string(), Value::String(arguments));
                }
                _ => {
                    map.insert("arguments".to_string(), Value::String(arguments));
                }
            }
        }
        _ => {}
    }

    map
}

/// Calculates the line number of an instruction in the source file.
///
/// # Arguments
///
/// * `ins` - The instruction
/// * `content` - The full Dockerfile content
///
/// # Returns
///
/// The 1-based line number, or None if it cannot be determined
pub fn get_line_number(ins: &Instruction, content: &str) -> Option<usize> {
    let span = match ins {
        Instruction::From(f) => &f.span,
        Instruction::Run(r) => &r.span,
        Instruction::Cmd(c) => &c.span,
        Instruction::Label(l) => &l.span,
        Instruction::Env(e) => &e.span,
        Instruction::Copy(c) => &c.span,
        Instruction::Entrypoint(e) => &e.span,
        Instruction::Arg(a) => &a.span,
        Instruction::Misc(m) => &m.span,
    };

    // Convert byte offset to line number by counting newlines
    let line_num = content[..span.start]
        .chars()
        .filter(|&c| c == '\n')
        .count() + 1;

    Some(line_num)
}

/// Finds the last USER instruction in a stage.
///
/// # Arguments
///
/// * `stage` - The Dockerfile stage to search
///
/// # Returns
///
/// The username specified in the last USER instruction, or None if not found
pub fn find_last_user_instruction(stage: &Stage) -> Option<String> {
    stage.instructions.iter().rev().find_map(|ins| {
        if let Instruction::Misc(m) = ins {
            if m.instruction.content.to_uppercase() == "USER" {
                return Some(m.arguments.to_string().trim().to_string());
            }
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dockerfile_parser::Dockerfile;

    #[test]
    fn test_get_instruction_kind_from() {
        let dockerfile = "FROM nginx:1.20";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[0];

        assert_eq!(get_instruction_kind(instruction), "FROM");
    }

    #[test]
    fn test_get_instruction_kind_run() {
        let dockerfile = "FROM nginx\nRUN apt-get update";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[1];

        assert_eq!(get_instruction_kind(instruction), "RUN");
    }

    #[test]
    fn test_get_instruction_kind_user() {
        let dockerfile = "FROM nginx\nUSER nobody";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[1];

        assert_eq!(get_instruction_kind(instruction), "USER");
    }

    #[test]
    fn test_instruction_to_map_from_with_tag() {
        let dockerfile = "FROM nginx:1.20";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[0];

        let map = instruction_to_map(instruction);

        assert_eq!(map.get("from.tag").unwrap(), &Value::String("1.20".to_string()));
        assert_eq!(map.get("from.image").unwrap(), &Value::String("nginx".to_string()));
    }

    #[test]
    fn test_instruction_to_map_from_without_tag() {
        let dockerfile = "FROM nginx";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[0];

        let map = instruction_to_map(instruction);

        // Should default to "latest" when no tag specified
        assert_eq!(map.get("from.tag").unwrap(), &Value::String("latest".to_string()));
    }

    #[test]
    fn test_instruction_to_map_user() {
        let dockerfile = "FROM nginx\nUSER nobody";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[1];

        let map = instruction_to_map(instruction);

        assert_eq!(map.get("user").unwrap(), &Value::String("nobody".to_string()));
    }

    #[test]
    fn test_instruction_to_map_expose() {
        let dockerfile = "FROM nginx\nEXPOSE 8080";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[1];

        let map = instruction_to_map(instruction);

        assert_eq!(map.get("port").unwrap(), &Value::String("8080".to_string()));
    }

    #[test]
    fn test_instruction_to_map_env() {
        let dockerfile = "FROM nginx\nENV API_KEY=secret123";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[1];

        let map = instruction_to_map(instruction);

        assert_eq!(map.get("env.key").unwrap(), &Value::String("API_KEY".to_string()));
        assert!(map.contains_key("env.value"));
    }

    #[test]
    fn test_get_line_number_first_line() {
        let content = "FROM nginx:1.20\nRUN apt-get update";
        let parsed = Dockerfile::parse(content).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[0];

        let line = get_line_number(instruction, content);

        assert_eq!(line, Some(1));
    }

    #[test]
    fn test_get_line_number_second_line() {
        let content = "FROM nginx:1.20\nRUN apt-get update";
        let parsed = Dockerfile::parse(content).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[1];

        let line = get_line_number(instruction, content);

        assert_eq!(line, Some(2));
    }

    #[test]
    fn test_get_line_number_with_empty_lines() {
        let content = "FROM nginx:1.20\n\n\nRUN apt-get update";
        let parsed = Dockerfile::parse(content).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[1];

        let line = get_line_number(instruction, content);

        assert_eq!(line, Some(4));
    }

    #[test]
    fn test_find_last_user_instruction_found() {
        let content = "FROM nginx\nRUN echo test\nUSER nobody";
        let parsed = Dockerfile::parse(content).unwrap();
        let stage = parsed.iter_stages().next().unwrap();

        let user = find_last_user_instruction(&stage);

        assert_eq!(user, Some("nobody".to_string()));
    }

    #[test]
    fn test_find_last_user_instruction_not_found() {
        let content = "FROM nginx\nRUN echo test";
        let parsed = Dockerfile::parse(content).unwrap();
        let stage = parsed.iter_stages().next().unwrap();

        let user = find_last_user_instruction(&stage);

        assert_eq!(user, None);
    }

    #[test]
    fn test_find_last_user_instruction_multiple_users() {
        let content = "FROM nginx\nUSER root\nRUN echo test\nUSER nobody";
        let parsed = Dockerfile::parse(content).unwrap();
        let stage = parsed.iter_stages().next().unwrap();

        let user = find_last_user_instruction(&stage);

        // Should return the LAST user instruction
        assert_eq!(user, Some("nobody".to_string()));
    }
}
