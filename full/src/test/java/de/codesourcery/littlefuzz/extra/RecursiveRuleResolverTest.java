package de.codesourcery.littlefuzz.extra;

import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import de.codesourcery.littlefuzz.core.Fuzzer;
import de.codesourcery.littlefuzz.core.RecursiveRuleResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RecursiveRuleResolverTest
{
    static class B {
        int c;
    }

    class A {
        int a;
        float b;
        B c;
    }

    static class D {
        int a;
        private D() {
        }
    }

    static class E {
        int a;
        D b;
    }

    static class G {
        int a;
        private G(int x) {
            a = x;
        }
    }

    static class F {
        int a;
        G b;
    }

    private Fuzzer fuzzer;

    @BeforeEach
    void setup() {
        fuzzer = new Fuzzer();
        final RandomUtils rnd = new RandomUtils( new Random() );
        final DifferentValueGenerator gen = new DifferentValueGenerator( 10 );
        rnd.setupDefaultRules( fuzzer, gen.differentValues() );
        fuzzer.setRuleResolver( new RecursiveRuleResolver( fuzzer.getRuleResolver() ) );
    }

    @Test
    void testRecursionWorksWithDefaultConstructor() {
        A test = new A();
        fuzzer.fuzz( test );
        assertThat( test.a ).isNotZero();
        assertThat( test.b ).isNotZero();
        assertThat( test.c ).isNotNull();
        assertThat( test.c.c ).isNotZero();
    }

    @Test
    void testRecursionWorksWithPrivateConstructor() {
        E test = new E();
        fuzzer.fuzz( test );
        assertThat( test.a ).isNotZero();
        assertThat( test.b ).isNotNull();
        assertThat( test.b.a ).isNotZero();
    }

    @Test
    void testRecursionFailsWithoutDefaultConstructor() {
        F test = new F();
        assertThatThrownBy( () -> fuzzer.fuzz( test ) ).isInstanceOf( RuntimeException.class);
    }
}