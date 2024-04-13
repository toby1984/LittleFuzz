package de.codesourcery.littlefuzz.core;

import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FuzzerTest
{
    static class Superclass {
        Long a;
    }

    static class Subclass extends Superclass {

        static Long c;

        Long b;
    }

    private Fuzzer f;
    private Random rnd;

    @BeforeEach
    public void setup() {
        f = new Fuzzer();
        rnd = new Random();
    }

    @Test
    public void testSuperclassIsConsidered() throws IllegalAccessException
    {
        f.addTypeRule( (ctx, setter) -> setter.set( rnd.nextLong() ), Long.TYPE, Long.class );

        final Subclass x = new Subclass();
        f.assignRandomValues( x, true );
        assertThat( x.a ).isNotNull();
        assertThat( x.b ).isNotNull();
        assertThat( Subclass.c ).isNull();
    }

    @Test
    public void testSuperclassIsConsidered2() throws IllegalAccessException
    {
        final Subclass x = new Subclass();
        f.addTypeRule( (ctx, setter) -> setter.set( rnd.nextLong() ), Long.class);
        f.assignRandomValues( x );
        assertThat( x.a ).isNotNull();
        assertThat( x.b ).isNotNull();
        assertThat( Subclass.c ).isNull();
    }

    @Test
    public void testSuperclassIsNotConsidered() throws IllegalAccessException
    {
        final Subclass x = new Subclass();
        f.addTypeRule( (ctx, setter) -> setter.set( rnd.nextLong() ), Long.class);
        f.assignRandomValues( x, false );
        assertThat( x.a ).isNull();
        assertThat( x.b ).isNotNull();
        assertThat( Subclass.c ).isNull();
    }

    static class Custom {
        long value;
    }

    @Test
    public void testCustomRule() throws IllegalAccessException
    {
        f.setTypeRule( IFuzzingRule.fromSupplier( () -> 42L ) , Long.TYPE );
        final Custom obj = f.assignRandomValues( new Custom() );
        assertThat( obj.value ).isEqualTo( 42L );
    }

    @Test
    public void testAddTypeRuleFailsOnConflict()
    {
        f.addTypeRule( IFuzzingRule.fromSupplier( () -> 42L ), Long.TYPE );
        assertThatThrownBy( () -> f.addTypeRule( IFuzzingRule.fromSupplier( () -> 42L ), Long.TYPE )
        ).isInstanceOf( IllegalArgumentException.class );
    }

    @Test
    public void testIgnoringEqualityCheckWorks() throws IllegalAccessException
    {
        final Custom obj = new Custom();
        obj.value = 42L;
        f.setTypeRule( IFuzzingRule.fromSupplier( () -> 42L ) , Long.TYPE );
        f.assignRandomValues( obj );
    }

    static class RuleTest {
        int a,b;
    }

    @Test
    public void testFieldRules() throws IllegalAccessException
    {
        final RuleTest obj = new RuleTest();
        f.addFieldRule( RuleTest.class, "a", IFuzzingRule.fromSupplier( () -> 42 ) );
        f.addFieldRule( RuleTest.class, "b", IFuzzingRule.fromSupplier( () -> 43 ) );

        f.assignRandomValues( obj );
        assertThat( obj.a ).isEqualTo( 42 );
        assertThat( obj.b ).isEqualTo( 43 );
    }

    static class ClearTest {int a;}

    @Test
    void testClearRules() throws IllegalAccessException
    {
        f.addTypeRule( (ctx, setter) -> setter.set( rnd.nextInt() ), Integer.TYPE );
        f.assignRandomValues( new ClearTest() );
        f.clearRules();
        assertThatThrownBy( () -> f.assignRandomValues( new ClearTest() ) ).isInstanceOf( RuntimeException.class );
    }

    @Test
    void testClearTypeRules() throws IllegalAccessException
    {
        f.addTypeRule( (ctx, setter) -> setter.set( rnd.nextInt() ), Integer.TYPE );
        f.assignRandomValues( new ClearTest() );
        f.clearTypeRules();
        assertThatThrownBy( () -> f.assignRandomValues( new ClearTest() ) ).isInstanceOf( RuntimeException.class );
    }

    class ClearTest2 {
        int a;
        ClearTest b;
    }

    @Test
    void testClearFieldRules() throws IllegalAccessException
    {
        f.clearTypeRules();
        f.addTypeRule( (context,setter) -> setter.set( (int) context.getFieldValue() + 1), Integer.TYPE);

        f.addFieldRule( ClearTest2.class, "b", (fieldInfo, setter) -> {} );
        f.assignRandomValues( new ClearTest2() );
        f.clearFieldRules();
        assertThatThrownBy( () -> f.assignRandomValues( new ClearTest2() ) ).isInstanceOf( RuntimeException.class );
    }
}