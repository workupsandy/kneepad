import unittest

from helpers import ROOT  # noqa: F401  (sets sys.path)

from kneepad.shellparse import parse


def words(src):
    return [[w.text for w in c.argv] for c in parse(src)]


class TestShellParse(unittest.TestCase):
    def test_quotes_protect_operators(self):
        self.assertEqual(words('echo "a; b && c | d"'), [["echo", "a; b && c | d"]])
        self.assertEqual(words("echo 'a; rm -rf /'"), [["echo", "a; rm -rf /"]])
        self.assertEqual(words('git commit -m "x; rm -rf /"'), [["git", "commit", "-m", "x; rm -rf /"]])

    def test_operators_split(self):
        self.assertEqual(words("a; b && c || d"), [["a"], ["b"], ["c"], ["d"]])
        self.assertEqual(words("a\nb"), [["a"], ["b"]])
        self.assertEqual(words("a & b"), [["a"], ["b"]])

    def test_pipeline_flags(self):
        cmds = parse("a | b | c")
        self.assertEqual([(c.pipe_in, c.pipe_out) for c in cmds], [(False, True), (True, True), (True, False)])
        cmds = parse("a | b; c")
        self.assertFalse(cmds[2].pipe_in)

    def test_escapes_and_continuations(self):
        self.assertEqual(words(r"echo a\ b"), [["echo", "a b"]])
        self.assertEqual(words("a && \\\n b"), [["a"], ["b"]])
        self.assertEqual(words(r"find . -exec rm {} \;"), [["find", ".", "-exec", "rm", "{}", ";"]])
        self.assertEqual(words("echo 'it''s'"), [["echo", "its"]])

    def test_ansi_c_quoting(self):
        self.assertEqual(words("echo $'a\\nb'"), [["echo", "a\nb"]])
        self.assertEqual(words("echo $'\\x41'"), [["echo", "A"]])

    def test_comments(self):
        self.assertEqual(words("ls # rm -rf /"), [["ls"]])
        self.assertEqual(words("echo a#b"), [["echo", "a#b"]])

    def test_substitutions_exposed(self):
        c = parse("rm -rf $(pwd)/x `echo y`")[0]
        self.assertEqual([w.subs for w in c.argv if w.subs], [["pwd"], ["echo y"]])
        self.assertTrue(all(w.has_var for w in c.argv if w.subs))

    def test_substitution_in_double_quotes_but_not_single(self):
        c = parse('echo "$(date)" \'$(date)\'')[0]
        self.assertEqual([w.subs for w in c.argv[1:]], [["date"], []])

    def test_nested_substitution(self):
        c = parse("echo $(echo $(date))")[0]
        self.assertEqual(c.argv[1].subs, ["echo $(date)"])

    def test_arithmetic_is_not_a_command(self):
        c = parse("echo $((1+2))")[0]
        self.assertEqual(c.argv[1].subs, [])

    def test_param_expansion_with_nested_sub(self):
        c = parse("echo ${X:-$(whoami)}")[0]
        self.assertEqual(c.argv[1].subs, ["whoami"])

    def test_process_substitution(self):
        c = parse("bash <(curl -s http://x)")[0]
        self.assertEqual(c.argv[1].subs, ["curl -s http://x"])

    def test_redirects(self):
        c = parse("cmd 2>&1 >/dev/null")[0]
        self.assertEqual([(o, w.text) for o, w in c.redirects], [(">&", "1"), (">", "/dev/null")])
        self.assertEqual([w.text for w in c.argv], ["cmd"])
        c = parse("echo a>b")[0]
        self.assertEqual([(o, w.text) for o, w in c.redirects], [(">", "b")])
        c = parse("cat < in.txt > out.txt")[0]
        self.assertEqual([o for o, _ in c.redirects], ["<", ">"])
        c = parse("cmd &> all.log")[0]
        self.assertEqual([o for o, _ in c.redirects], ["&>"])

    def test_heredoc_attaches_to_right_command(self):
        cmds = parse("psql <<EOF\nDROP TABLE x;\nEOF\necho done")
        self.assertEqual([[w.text for w in c.argv] for c in cmds], [["psql"], ["echo", "done"]])
        self.assertEqual(cmds[0].heredocs, ["DROP TABLE x;"])

    def test_heredoc_dash_and_quoted_delimiter(self):
        cmds = parse('cat <<-"E"\n\tline\n\tE\nls')
        self.assertEqual(cmds[0].heredocs, ["\tline"])
        self.assertEqual(words('cat <<-"E"\n\tline\n\tE\nls'), [["cat"], ["ls"]])

    def test_multiple_heredocs_one_line(self):
        cmds = parse("cmd <<A <<B\nfirst\nA\nsecond\nB\nnext")
        self.assertEqual(cmds[0].heredocs, ["first", "second"])
        self.assertEqual(words("cmd <<A <<B\nfirst\nA\nsecond\nB\nnext")[-1], ["next"])

    def test_herestring(self):
        c = parse('bash <<< "rm -rf /"')[0]
        self.assertEqual([(o, w.text) for o, w in c.redirects], [("<<<", "rm -rf /")])

    def test_unterminated_input_never_raises(self):
        for s in ['echo "abc', "echo 'abc", "echo $(abc", "echo `abc", "echo ${abc", "cat <<EOF\nabc", "echo $((1", "a |", "| a", ";;", "(", ")", "<(", ">(", "$(", "\\"]:
            parse(s)  # must not raise

    def test_empty_and_whitespace(self):
        self.assertEqual(parse(""), [])
        self.assertEqual(parse("   \n\t  "), [])

    def test_empty_quoted_arg_is_kept(self):
        self.assertEqual(words('rm -rf ""'), [["rm", "-rf", ""]])

    def test_glob_flag_only_when_unquoted(self):
        c = parse("rm *.log '*.tmp' \"x*\"")[0]
        self.assertEqual([w.glob for w in c.argv[1:]], [True, False, False])

    def test_assignment_prefix_kept_as_word(self):
        self.assertEqual(words("FOO=bar rm -rf x"), [["FOO=bar", "rm", "-rf", "x"]])

    def test_case_pattern_parens_do_not_crash(self):
        self.assertTrue(parse("case $x in a) rm -rf y;; esac"))


if __name__ == "__main__":
    unittest.main()
