use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkillDependency {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkillDependencyInfo {
    pub(crate) skill_name: String,
    pub(crate) dependency: SkillDependency,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkillDependencyResponse {
    pub(crate) values: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct SkillFrontmatter {
    #[serde(default)]
    dependencies: Vec<SkillDependencyEntry>,
}

#[derive(Debug, Deserialize)]
struct SkillDependencyEntry {
    #[serde(rename = "type")]
    dep_type: String,
    name: Option<String>,
    description: Option<String>,
}

pub(crate) fn parse_env_var_dependencies(contents: &str) -> Vec<SkillDependency> {
    let Some(frontmatter) = extract_frontmatter(contents) else {
        return Vec::new();
    };

    let parsed: SkillFrontmatter = match serde_yaml::from_str(&frontmatter) {
        Ok(parsed) => parsed,
        Err(_) => return Vec::new(),
    };

    parsed
        .dependencies
        .into_iter()
        .filter_map(|entry| {
            if entry.dep_type != "env_var" {
                return None;
            }
            let name = entry.name.map(|value| sanitize_single_line(&value))?;
            if name.is_empty() {
                return None;
            }
            let description = entry
                .description
                .map(|value| sanitize_single_line(&value))
                .filter(|value| !value.is_empty());
            Some(SkillDependency { name, description })
        })
        .collect()
}

fn extract_frontmatter(contents: &str) -> Option<String> {
    let mut lines = contents.lines();
    if !matches!(lines.next(), Some(line) if line.trim() == "---") {
        return None;
    }

    let mut frontmatter_lines: Vec<&str> = Vec::new();
    let mut found_closing = false;
    for line in lines.by_ref() {
        if line.trim() == "---" {
            found_closing = true;
            break;
        }
        frontmatter_lines.push(line);
    }

    if frontmatter_lines.is_empty() || !found_closing {
        return None;
    }

    Some(frontmatter_lines.join("\n"))
}

fn sanitize_single_line(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}
